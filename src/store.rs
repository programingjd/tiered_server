use crate::env;
use crate::env::Key::StoreEncryptionKey;
use crate::env::secret_value;
use crate::otp::ValidationMethod;
use base64_simd::URL_SAFE_NO_PAD;
use chrono::Utc;
use futures_lite::StreamExt;
use hyper::body::Bytes;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::local::LocalFileSystem;
use object_store::path::Path;
use object_store::{GetResultPayload, ObjectStore, PutPayload};
use ring::aead::{
    AES_256_GCM, Aad, BoundKey, LessSafeKey, Nonce, NonceSequence, OpeningKey, UnboundKey,
};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::iter;
use std::sync::LazyLock;

pub(crate) async fn get_otp(token: &str) -> Option<ValidationMethod> {
    let store = store()?;
    let path = Path::from(format!("/otp/{token}"));
    let result = store.get(&path).await.ok()?;
    let now = Utc::now();
    let duration = now
        .signed_duration_since(result.meta.last_modified)
        .num_minutes();
    let payload = if duration > -1_i64 && duration < 20_i64 {
        download(result.payload).await
    } else {
        None
    };
    let _ = store.delete(&path).await;
    let payload = payload?;
    let nonce: [u8; 12] = payload[0..12].try_into().unwrap();
    let encrypted_base64 = &payload[12..];
    decrypt(nonce, encrypted_base64)
}

pub(crate) async fn set_otp(token: &str, validation_method: &ValidationMethod) -> Option<()> {
    let store = store()?;
    let path = Path::from(format!("/otp/{token}"));
    let encrypted = encrypt(validation_method);
    let payload = PutPayload::from_iter(
        iter::once(Bytes::from_owner(encrypted.nonce))
            .chain(iter::once(Bytes::from_owner(encrypted.encrypted_base64))),
    );
    match store.put(&path, payload).await {
        Ok(_) => Some(()),
        _ => None,
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
    let region = secret_value(env::Key::S3Region)?;
    let endpoint = secret_value(env::Key::S3Endpoint)?;
    let bucket = secret_value(env::Key::S3Bucket)?;
    let access_key = secret_value(env::Key::S3AccessKey)?;
    let secret_key = secret_value(env::Key::S3SecretKey)?;
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
                    Ok(chunk) => vec.extend_from_slice(&chunk),
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
    serde_json::from_reader(encrypted.as_slice()).ok()
}
