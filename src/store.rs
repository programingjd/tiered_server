use crate::env;
use crate::env::ConfigurationKey::StoreEncryptionKey;
use crate::env::secret_value;
use base64_simd::URL_SAFE_NO_PAD;
use futures_lite::{StreamExt, stream};
use hyper::body::Bytes;
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
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};
use std::{iter, thread};
use tar::{Archive, Builder, Header};
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{debug, trace, warn};

static SNAPSHOT: LazyLock<Pinboard<Arc<Snapshot>>> = LazyLock::new(Pinboard::new_empty);

pub struct Snapshot {
    entries: HashMap<String, Entry>,
    #[allow(dead_code)]
    timestamp: u32,
}

struct Entry {
    data: Vec<u8>,
    timestamp: u32,
}

static CACHE_VERSION: AtomicU32 = AtomicU32::new(0);

fn update_store_cache_loop() {
    CACHE_VERSION.fetch_add(1, std::sync::atomic::Ordering::Release);
    thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap()
            .block_on(async move {
                let mut delay = interval(Duration::from_millis(1_000_u64));
                delay.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    delay.tick().await;
                    if let Some(snapshot) = new_snapshot().await {
                        SNAPSHOT.set(Arc::new(snapshot));
                        let version =
                            CACHE_VERSION.fetch_add(1, std::sync::atomic::Ordering::Release);
                        trace!("snapshot updated (version: {version})");
                    } else {
                        warn!("update snapshot failed");
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
                    .block_on(async move { new_snapshot().await })
            })
            .join()
            .ok()
            .flatten()
            .expect("failed to create snapshot"),
        );
        SNAPSHOT.set(snapshot.clone());
        update_store_cache_loop();
        snapshot
    }
}

pub async fn new_snapshot() -> Option<Snapshot> {
    let reference = SNAPSHOT.get_ref();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let store = store()?;
    let mut entries =
        HashMap::with_capacity(256 + reference.map(|it| it.entries.len()).unwrap_or(256));
    let mut iter = store.list(None);
    while let Some(metadata) = iter.next().await {
        if metadata.is_err() {
            return None;
        }
        let metadata = metadata.unwrap();
        let timestamp = metadata.last_modified.timestamp() as u32;
        let reference = SNAPSHOT.get_ref().map(|it| it.clone());
        let data = if let Some(existing) = reference
            .as_ref()
            .and_then(|it| it.entries.get(metadata.location.as_ref()))
            .filter(|it| it.timestamp == timestamp)
        {
            existing.data.clone()
        } else {
            debug!("new cache entry: {}", &metadata.location);
            let result = store.get(&metadata.location).await.ok()?;
            download(result.payload).await?
        };
        entries.insert(metadata.location.into(), Entry { timestamp, data });
    }
    Some(Snapshot { entries, timestamp })
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
                    sleep(Duration::from_millis(50)).await;
                    Some(())
                } else {
                    let version = CACHE_VERSION.load(std::sync::atomic::Ordering::Acquire);
                    if version == 0 {
                        return Some(());
                    }
                    trace!("cache version before update: {version}");
                    let mut retries = 0_u8;
                    let mut delay = interval(Duration::from_millis(300_u64));
                    delay.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    loop {
                        delay.tick().await;
                        if retries == 10 {
                            warn!("cache update delay too long");
                            return None;
                        }
                        let current_version =
                            CACHE_VERSION.load(std::sync::atomic::Ordering::Acquire);
                        trace!("cache version: {current_version}");
                        if current_version > version {
                            return Some(());
                        }
                        retries += 1;
                    }
                }
            }
            Err(err) => {
                warn!("{err:?}");
                None
            }
        }
    }
    pub async fn delete<T: AsRef<str>>(paths: impl Iterator<Item = T> + Send) -> Option<()> {
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
        Some(())
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
                //     .map_err(|err| {
                //         warn!("{err:?}");
                //         err
                //     })
                //     .ok()?;
                header.set_size(entry.data.len() as u64);
                header.set_mtime(entry.timestamp as u64);
                header.set_cksum();
                tar.append_data(&mut header, path, entry.data.as_slice())
                    .map_err(|err| {
                        warn!("{err:?}");
                        err
                    })
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
        Self::delete(keys.into_iter()).await
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
    let region = secret_value(env::ConfigurationKey::S3Region)?;
    let endpoint = secret_value(env::ConfigurationKey::S3Endpoint)?;
    let bucket = secret_value(env::ConfigurationKey::S3Bucket)?;
    let access_key = secret_value(env::ConfigurationKey::S3AccessKey)?;
    let secret_key = secret_value(env::ConfigurationKey::S3SecretKey)?;
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

async fn download(payload: GetResultPayload) -> Option<Vec<u8>> {
    let mut vec = Vec::new();
    match payload {
        GetResultPayload::Stream(mut stream) => {
            while let Some(result) = stream.next().await {
                match result {
                    Ok(chunk) => vec.extend(chunk.iter()),
                    Err(_) => return None,
                }
            }
        }
        GetResultPayload::File(mut file, ..) => {
            if file.read_to_end(&mut vec).is_err() {
                return None;
            };
        }
    }
    Some(vec)
}

#[derive(Serialize, Deserialize)]
struct Test {
    message: String,
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
        .map_err(|err| {
            warn!("{err:?}");
            err
        })
        .ok()
}
