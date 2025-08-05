use crate::env::ConfigurationKey::StoreEncryptionKey;
use crate::env::{ConfigurationKey, secret_value};
use base64_simd::URL_SAFE_NO_PAD;
use futures::future::try_join_all;
use futures::{StreamExt, stream};
use hyper::body::Bytes;
use leaky_bucket::RateLimiter;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::local::LocalFileSystem;
use object_store::path::Path;
use object_store::{GetResultPayload, ObjectStore, PutPayload};
use pinboard::Pinboard;
use ring::aead::{
    AES_256_GCM, Aad, BoundKey, LessSafeKey, Nonce, NonceSequence, OpeningKey, UnboundKey,
};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use std::{iter, thread};
use tar::{Archive, Builder, Header};
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, info, trace, warn};

static SNAPSHOT: LazyLock<Pinboard<Arc<Snapshot>>> = LazyLock::new(Pinboard::new_empty);

static RATE_LIMITER: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::builder()
        .refill(
            secret_value(ConfigurationKey::StoreRateLimit)
                .and_then(|it| it.parse().ok())
                .unwrap_or(100),
        )
        .fair(true)
        .interval(Duration::from_secs(1))
        .build()
});

pub struct Snapshot {
    entries: HashMap<String, Entry>,
    revision: u32,
    downloads: u32,
}

struct Entry {
    data: Vec<u8>,
    timestamp: u32,
}

static CACHE_REVISION: AtomicU32 = AtomicU32::new(0);

fn update_store_cache_loop() {
    thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_time()
            .enable_io()
            .build()
            .unwrap()
            .block_on(async move {
                let mut skip_counter: u8 = 0;
                // the delay needs to be at least 1 second so that we don't miss later updates
                // with the same timestamp (timestamp resolution is 1 second)
                let mut delay = interval(Duration::from_millis(1_500_u64));
                delay.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    let cache_revision = CACHE_REVISION.load(Ordering::Acquire);
                    delay.tick().await;
                    let remote_revision = snapshot_revision().await.unwrap_or_default();
                    if remote_revision == cache_revision {
                        skip_counter += 1;
                        // update cache anyway every minute (40 * 1500ms)
                        if skip_counter == 40 {
                            skip_counter = 0;
                        } else {
                            continue;
                        }
                    }
                    if let Some(snapshot) = new_snapshot().await {
                        let revision = snapshot.revision;
                        let downloads = snapshot.downloads;
                        let len = snapshot.entries.len();
                        SNAPSHOT.set(Arc::new(snapshot));
                        CACHE_REVISION.store(revision, Ordering::Release);
                        debug!("snapshot updated (revision: {revision}, {len} entries, {downloads} downloads)");
                    } else {
                        warn!("snapshot update failed");
                    }
                }
            });
    });
}

pub fn snapshot() -> Arc<Snapshot> {
    if let Some(snapshot) = SNAPSHOT.get_ref() {
        snapshot.clone()
    } else {
        let snapshot = Arc::new(
            thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .enable_io()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        new_snapshot().await.or_else(|| {
                            warn!("failed to create snapshot");
                            None
                        })
                    })
            })
            .join()
            .inspect_err(|err| warn!("{err:?}"))
            .ok()
            .flatten()
            .expect("failed to create snapshot"),
        );
        SNAPSHOT.set(snapshot.clone());
        CACHE_REVISION.store(snapshot.revision, Ordering::Release);
        info!("store cache is ready");
        update_store_cache_loop();
        snapshot
    }
}

async fn snapshot_revision() -> Option<u32> {
    let revision = store()?
        .head(&Path::from("rev"))
        .await
        .inspect_err(|err| warn!("failed to get remove store revision:\n{err:?}"))
        .ok()?
        .last_modified
        .timestamp() as u32;
    trace!("remote cache revision: {revision}");
    Some(revision)
}

pub async fn new_snapshot() -> Option<Snapshot> {
    let reference = SNAPSHOT.get_ref();
    let reference = reference.as_deref();
    let len = if let Some(reference) = reference {
        let len = reference.entries.len();
        debug!(
            "differential snapshot (initial revision: {}, {len} entries)",
            reference.revision
        );
        256 + len
    } else {
        debug!("full snapshot");
        256
    };
    let store = store()?;
    let mut entries = HashMap::with_capacity(len);
    let mut iter = store.list(None);
    let mut pending = vec![];
    let store = Arc::new(store);
    let mut revision: u32 = 0;
    while let Some(metadata) = iter.next().await {
        match metadata {
            Ok(metadata) => {
                if metadata.size == 0 {
                    if metadata.location.as_ref() == "rev" {
                        let timestamp = metadata.last_modified.timestamp() as u32;
                        revision = timestamp;
                    }
                    continue;
                }
                let timestamp = metadata.last_modified.timestamp() as u32;
                if let Some(existing) =
                    reference.and_then(|it| it.entries.get(metadata.location.as_ref()))
                {
                    if existing.timestamp == timestamp {
                        let data = existing.data.clone();
                        entries.insert(metadata.location.into(), Entry { timestamp, data });
                    } else {
                        let store = store.clone();
                        pending.push(download_entry(
                            metadata.location,
                            timestamp,
                            store,
                            Some(existing.timestamp),
                        ));
                    }
                } else {
                    let store = store.clone();
                    pending.push(download_entry(metadata.location, timestamp, store, None));
                }
            }
            Err(err) => {
                warn!("{err:?}");
                return None;
            }
        }
    }
    let downloads: u32 = pending.len() as u32;
    if !pending.is_empty() {
        for (key, timestamp, data) in try_join_all(pending).await.ok()? {
            entries.insert(key, Entry { timestamp, data });
        }
    }
    Some(Snapshot {
        entries,
        revision,
        downloads,
    })
}

async fn download_entry(
    path: Path,
    timestamp: u32,
    store: Arc<Box<dyn ObjectStore>>,
    existing: Option<u32>,
) -> Result<(String, u32, Vec<u8>), ()> {
    RATE_LIMITER.acquire_one().await;
    if let Some(existing) = existing {
        debug!("updated cache entry: {path} ({timestamp} != {existing})");
    }
    debug!("new cache entry: {path}");
    let result = store.get(&path).await.map_err(|err| {
        warn!("{err:?}");
    })?;
    Ok((
        path.into(),
        result.meta.last_modified.timestamp() as u32,
        download(result.payload).await?,
    ))
}

impl Snapshot {
    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Option<T> {
        self.entries.get(path).and_then(|entry| {
            let payload = entry.data.as_slice();
            let nonce: [u8; 12] = payload[0..12].try_into().unwrap();
            let encrypted_base64 = &payload[12..];
            decrypt(nonce, encrypted_base64)
        })
    }
    pub fn list<T: DeserializeOwned>(&self, prefix: &str) -> impl Iterator<Item = (&str, T)> {
        self.entries.iter().filter_map(move |(k, v)| {
            if k.starts_with(prefix) {
                let payload = v.data.as_slice();
                let nonce: [u8; 12] = payload[0..12].try_into().unwrap();
                let encrypted_base64 = &payload[12..];
                decrypt(nonce, encrypted_base64).map(|it| (k.as_str(), it))
            } else {
                None
            }
        })
    }
    pub async fn set_and_wait_for_update<T: Serialize>(path: &str, data: &T) -> Option<()> {
        Self::set(path, data, false).await
    }
    pub async fn set_and_return_before_update<T: Serialize>(path: &str, data: &T) -> Option<()> {
        Self::set(path, data, true).await
    }
    async fn set<T: Serialize>(path: &str, data: &T, skip_update: bool) -> Option<()> {
        let store = store()?;
        let path = Path::from(path);
        let encrypted = encrypt(data);
        let payload = PutPayload::from_iter(
            iter::once(Bytes::from_owner(encrypted.nonce))
                .chain(iter::once(Bytes::from_owner(encrypted.encrypted_base64))),
        );
        match store.put(&path, payload).await {
            Ok(_) => {
                if skip_update {
                    let _ = store
                        .put(&Path::from("rev"), PutPayload::new())
                        .await
                        .inspect_err(|err| warn!("failed to update store revision {err:?}"));
                    RATE_LIMITER.acquire_one().await;
                    Some(())
                } else {
                    Self::wait_for_new_revision(&store).await
                }
            }
            Err(err) => {
                warn!("{err:?}");
                RATE_LIMITER.acquire_one().await;
                None
            }
        }
    }

    pub async fn delete_and_wait_for_update<T: AsRef<str>>(
        paths: impl Iterator<Item = T> + Send,
    ) -> Option<()> {
        Self::delete(paths, false).await
    }

    pub async fn delete_and_return_before_update<T: AsRef<str>>(
        paths: impl Iterator<Item = T> + Send,
    ) -> Option<()> {
        Self::delete(paths, true).await
    }

    pub async fn delete<T: AsRef<str>>(
        paths: impl Iterator<Item = T> + Send,
        skip_update: bool,
    ) -> Option<()> {
        let store = store()?;
        let mut iter = store.delete_stream(
            stream::iter(paths.into_iter().map(|it| {
                let path = Path::from(it.as_ref());
                debug!("del cache entry: {path}");
                Ok(path)
            }))
            .boxed(),
        );
        while let Some(result) = iter.next().await {
            if let Err(err) = result {
                warn!("{err:?}");
            }
        }
        if skip_update {
            let _ = store
                .put(&Path::from("rev"), PutPayload::new())
                .await
                .inspect_err(|err| warn!("failed to update store revision {err:?}"));
            RATE_LIMITER.acquire_one().await;
            Some(())
        } else {
            Self::wait_for_new_revision(&store).await
        }
    }

    async fn wait_for_new_revision(store: &dyn ObjectStore) -> Option<()> {
        let revision = CACHE_REVISION.load(Ordering::Acquire);
        let _ = store
            .put(&Path::from("rev"), PutPayload::new())
            .await
            .inspect_err(|err| warn!("failed to update store revision {err:?}"));
        RATE_LIMITER.acquire_one().await;
        trace!("cache revision before update: {revision}");
        let mut retries = 0_u8;
        let mut delay = interval(Duration::from_millis(300_u64));
        delay.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            delay.tick().await;
            if retries == 10 {
                warn!("cache update delay too long");
                return None;
            }
            let current_revision = CACHE_REVISION.load(Ordering::Acquire);
            trace!("cache revision: {current_revision}");
            if current_revision > revision {
                return Some(());
            }
            retries += 1;
        }
    }

    pub async fn backup(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        {
            let mut tar = Builder::new(&mut bytes);
            for (path, entry) in self.entries.iter() {
                let mut header = Header::new_gnu();
                debug!("backup: {path}");
                // header
                //     .set_path(path)
                //     .inspect_err(|err| warn!("{err:?}"))
                //     .ok()?;
                header.set_size(entry.data.len() as u64);
                header.set_mtime(entry.timestamp as u64);
                header.set_cksum();
                tar.append_data(&mut header, path, entry.data.as_slice())
                    .inspect_err(|err| warn!("{err:?}"))
                    .ok()?;
            }
            tar.finish().ok()?;
        }
        Some(bytes)
    }
    pub async fn restore(&self, bytes: &[u8]) -> Option<()> {
        let mut keys = self.entries.keys().collect::<BTreeSet<_>>();
        let mut tar = Archive::new(bytes);
        let store = store()?;
        for entry in tar.entries().ok()? {
            let mut entry = entry.ok()?;
            let key = entry
                .path()
                .as_ref()
                .ok()
                .and_then(|it| it.to_str())?
                .to_string();
            keys.remove(&key);
            let path = Path::from(key);
            let mut data = Vec::new();
            entry.read_to_end(&mut data).ok()?;
            store.put(&path, PutPayload::from(data)).await.ok()?;
        }
        Self::delete_and_return_before_update(keys.into_iter()).await
    }
}

fn store() -> Option<Box<dyn ObjectStore>> {
    match s3_store() {
        Some(store) => Some(Box::new(store)),
        None => match local_store() {
            Some(store) => Some(Box::new(store)),
            None => None,
        },
    }
}

fn s3_store() -> Option<AmazonS3> {
    let region = secret_value(ConfigurationKey::S3Region)?;
    let endpoint = secret_value(ConfigurationKey::S3Endpoint)?;
    let bucket = secret_value(ConfigurationKey::S3Bucket)?;
    let access_key = secret_value(ConfigurationKey::S3AccessKey)?;
    let secret_key = secret_value(ConfigurationKey::S3SecretKey)?;
    AmazonS3Builder::new()
        .with_region(region)
        .with_endpoint(endpoint)
        .with_bucket_name(bucket)
        .with_access_key_id(access_key)
        .with_secret_access_key(secret_key)
        .build()
        .ok()
}

fn local_store() -> Option<LocalFileSystem> {
    LocalFileSystem::new_with_prefix("storage").ok()
}

async fn download(payload: GetResultPayload) -> Result<Vec<u8>, ()> {
    let mut vec = Vec::new();
    match payload {
        GetResultPayload::Stream(mut stream) => {
            while let Some(result) = stream.next().await {
                match result {
                    Ok(chunk) => vec.extend(chunk.iter()),
                    Err(err) => {
                        warn!("{err:?}");
                        return Err(());
                    }
                }
            }
        }
        GetResultPayload::File(mut file, ..) => {
            if file.read_to_end(&mut vec).is_err() {
                return Err(());
            };
        }
    }
    Ok(vec)
}

struct SingleUseNonce([u8; 12]);
impl NonceSequence for SingleUseNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

//noinspection SpellCheckingInspection
static ENCRYPTION_KEY: LazyLock<&'static str> = LazyLock::new(|| {
    secret_value(StoreEncryptionKey).unwrap_or("BEi1IBgn9rj6aNUewc4ENyJiKSiUj_c4J7jLKZTg1Ro")
});

struct EncryptedObject {
    nonce: [u8; 12],
    encrypted_base64: String,
}

fn encrypt<T: Serialize>(value: &T) -> EncryptedObject {
    let mut serialized = serde_json::to_vec(value).unwrap();
    let mut nonce = [0u8; 12];
    SystemRandom::new().fill(&mut nonce).unwrap();
    let key = LessSafeKey::new(
        UnboundKey::new(
            &AES_256_GCM,
            URL_SAFE_NO_PAD
                .decode_to_vec(ENCRYPTION_KEY.as_bytes())
                .unwrap()
                .as_slice(),
        )
        .unwrap(),
    );
    let aad = Aad::empty();
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), aad, &mut serialized)
        .unwrap();
    let encrypted_base64 = URL_SAFE_NO_PAD.encode_to_string(serialized.as_slice());
    EncryptedObject {
        nonce,
        encrypted_base64,
    }
}

fn decrypt<T: DeserializeOwned>(nonce: [u8; 12], encrypted_base64: &[u8]) -> Option<T> {
    let mut encrypted = URL_SAFE_NO_PAD.decode_to_vec(encrypted_base64).ok()?;
    let mut key = OpeningKey::new(
        UnboundKey::new(
            &AES_256_GCM,
            URL_SAFE_NO_PAD
                .decode_to_vec(ENCRYPTION_KEY.as_bytes())
                .unwrap()
                .as_slice(),
        )
        .unwrap(),
        SingleUseNonce(nonce),
    );
    let aad = Aad::empty();
    let len = key.open_in_place(aad, &mut encrypted).ok()?.len();
    while encrypted.len() > len {
        encrypted.pop();
    }
    serde_json::from_reader(encrypted.as_slice())
        .inspect_err(|err| warn!("{err:?}"))
        .ok()
}
