use crate::browser::BrowserInfo;
use crate::iter::{pair, single};
use base64_simd::URL_SAFE_NO_PAD;
use ring::signature;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
};
use serde::{Deserialize, Serialize};
use simple_asn1::{ASN1Block, BigUint, from_der};
use std::fmt::Write;
use tracing::{debug, warn};

pub(crate) mod challenge;
pub(crate) mod credential_creations_options;
pub(crate) mod credential_request_options;
pub(crate) mod credentials;

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
pub(crate) struct PassKey {
    pub(crate) id: String,
    pub(crate) timestamp: u32,
    pub(crate) browser_info: BrowserInfo,
    subject_public_key_info: String,
}

impl PassKey {
    pub(crate) fn verify(
        &self,
        signature: &[u8],
        authenticator_data: &[u8],
        client_data_hash: &[u8],
    ) -> bool {
        let subject_public_key_info = URL_SAFE_NO_PAD
            .decode_to_vec(self.subject_public_key_info.clone())
            .unwrap();
        let subject_public_key_info = match from_der(&subject_public_key_info).ok().and_then(single)
        {
            Some(ASN1Block::Sequence(_, blocks)) => blocks,
            _ => {
                warn!("invalid SubjectPublicKeyInfo");
                return false;
            }
        };
        debug!("{}", format!("{subject_public_key_info:?}"));
        let (algorithm_oid, subject_public_key) = match pair(subject_public_key_info) {
            Some((ASN1Block::Sequence(_, blocks), ASN1Block::BitString(_, _, bytes))) => {
                match blocks.first() {
                    Some(ASN1Block::ObjectIdentifier(_, it)) => {
                        let it = match it.as_vec::<&BigUint>() {
                            Ok(it) => it,
                            Err(_) => {
                                warn!("invalid AlgorithmIdentifier");
                                return false;
                            }
                        };
                        let mut oid = String::with_capacity(it.len() * 5);
                        let mut iter = it.iter();
                        if let Some(first) = iter.next() {
                            let _ = write!(oid, "{first}");
                        }
                        for it in iter {
                            oid.push('.');
                            let _ = write!(oid, "{it}");
                        }
                        (oid, bytes)
                    }
                    _ => {
                        warn!("invalid AlgorithmIdentifier");
                        return false;
                    }
                }
            }
            _ => {
                warn!("invalid SubjectPublicKeyInfo");
                return false;
            }
        };
        match algorithm_oid.as_str() {
            "1.3.101.112" => {
                // ED25519
                if subject_public_key.len() != 32 {
                    warn!("invalid ED25519 subject public key");
                    return false;
                }
                let x = &subject_public_key;
                let public_key = signature::UnparsedPublicKey::new(&ED25519, x);
                let mut payload =
                    Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
                payload.extend(authenticator_data.iter());
                payload.extend(client_data_hash.iter());
                public_key.verify(&payload, signature).is_ok()
            }
            "1.2.840.10045.2.1" => {
                // ES256
                let sec1 = &subject_public_key;
                let public_key = signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, sec1);
                let mut payload =
                    Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
                payload.extend(authenticator_data.iter());
                payload.extend(client_data_hash.iter());
                public_key.verify(&payload, signature).is_ok()
            }
            "1.2.840.113549.1.1.1" => {
                // RSA256
                let (n, e) = match from_der(&subject_public_key).ok().and_then(single) {
                    Some(ASN1Block::Sequence(_, blocks)) => match pair(blocks) {
                        Some((ASN1Block::Integer(_, n), ASN1Block::Integer(_, e))) => {
                            let n = match n.to_biguint() {
                                Some(it) => it.to_bytes_be(),
                                None => {
                                    warn!("invalid RSA n value");
                                    return false;
                                }
                            };
                            let e = match e.to_biguint() {
                                Some(it) => it.to_bytes_be(),
                                None => {
                                    warn!("invalid RSA e value");
                                    return false;
                                }
                            };
                            (n, e)
                        }
                        _ => {
                            warn!("invalid RSA subject public key");
                            return false;
                        }
                    },
                    _ => {
                        warn!("invalid RSA subject public key");
                        return false;
                    }
                };
                let public_key = RsaPublicKeyComponents { n, e };
                // let public_key = signature::UnparsedPublicKey::new(
                //     &RSA_PKCS1_2048_8192_SHA256,
                //     subject_public_key,
                // );
                let mut payload =
                    Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
                payload.extend(authenticator_data.iter());
                payload.extend(client_data_hash.iter());
                public_key
                    .verify(&RSA_PKCS1_2048_8192_SHA256, &payload, signature)
                    .is_ok()
            }
            _ => {
                warn!("invalid algorithm OID");
                false
            }
        }
    }
    pub(crate) fn new(
        id: String,
        timestamp: u32,
        browser_info: BrowserInfo,
        alg: i16,
        subject_public_key_info: Vec<u8>,
    ) -> Option<Self> {
        match alg {
            -8 => debug!("ED25519"),
            -7 => debug!("ES256"),
            -257 => debug!("RS256"),
            it => {
                warn!("Unsupported algorithm: {it}");
                return None;
            }
        }
        Some(Self {
            id,
            timestamp,
            browser_info,
            subject_public_key_info: URL_SAFE_NO_PAD.encode_to_string(&subject_public_key_info),
        })
    }
}

#[cfg(test)]
mod tests_rsa {
    use super::PassKey;
    use crate::browser::BrowserInfo;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::rand_core::{OsRng, RngCore};
    use rsa::sha2::Sha256;
    use rsa::signature::{SignatureEncoding, Signer};

    #[test]
    fn verify_rsa256() {
        let key_count = 3_usize;
        let payload_count = 3_usize;
        let mut rng = OsRng;
        for i in 0..key_count {
            let pkcs8 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let public_key = pkcs8.to_public_key();
            let spki = public_key.to_public_key_der().unwrap().to_vec();
            let signing_key = SigningKey::<Sha256>::new(pkcs8);
            for j in 0..payload_count {
                let len = 10
                    + rng
                        .next_u32()
                        .to_be_bytes()
                        .into_iter()
                        .map(|it| it as u16)
                        .sum::<u16>() as usize;
                let index = (rng.next_u32() % (len as u32 - 5)) as usize;
                let mut payload = vec![0u8; len];
                rng.fill_bytes(&mut payload);
                let signature = signing_key.sign(&payload).to_vec();
                let passkey = PassKey::new(
                    format!("{i}_{j}_{len}__rsa256"),
                    0,
                    BrowserInfo::default(),
                    -257,
                    spki.clone(),
                )
                .unwrap();
                assert!(passkey.verify(&signature, &payload[..index], &payload[index..]));
            }
        }
    }
}

#[cfg(test)]
mod tests_ed25519 {
    use super::PassKey;
    use crate::browser::BrowserInfo;
    use ed25519_dalek::ed25519::signature::rand_core::{OsRng, RngCore};
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verify_ed25519() {
        let key_count = 3_usize;
        let payload_count = 3_usize;
        let mut rng = OsRng;
        for i in 0..key_count {
            let signing_key = SigningKey::generate(&mut rng);
            let public_key = signing_key.verifying_key();
            let spki = public_key.to_public_key_der().unwrap().to_vec();
            for j in 0..payload_count {
                let len = 10
                    + rng
                        .next_u32()
                        .to_be_bytes()
                        .into_iter()
                        .map(|it| it as u16)
                        .sum::<u16>() as usize;
                let index = (rng.next_u32() % (len as u32 - 5)) as usize;
                let mut payload = vec![0u8; len];
                rng.fill_bytes(&mut payload);
                let signature = signing_key.sign(&payload).to_vec();
                let passkey = PassKey::new(
                    format!("{i}_{j}_{len}__ed25519"),
                    0,
                    BrowserInfo::default(),
                    -8,
                    spki.clone(),
                )
                .unwrap();
                assert!(passkey.verify(&signature, &payload[..index], &payload[index..]));
            }
        }
    }
}

#[cfg(test)]
mod tests_es256 {
    use super::PassKey;
    use crate::browser::BrowserInfo;
    use p256::PublicKey;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::rand_core::{OsRng, RngCore};

    #[test]
    fn verify_es256() {
        let key_count = 3_usize;
        let payload_count = 3_usize;
        let mut rng = OsRng;
        for i in 0..key_count {
            let signing_key = SigningKey::random(&mut rng);
            let verifying_key = signing_key.verifying_key();
            let public_key =
                PublicKey::from_sec1_bytes(verifying_key.to_sec1_bytes().as_ref()).unwrap();
            let spki = p256::pkcs8::EncodePublicKey::to_public_key_der(&public_key)
                .unwrap()
                .to_vec();
            for j in 0..payload_count {
                let len = 10
                    + rng
                        .next_u32()
                        .to_be_bytes()
                        .into_iter()
                        .map(|it| it as u16)
                        .sum::<u16>() as usize;
                let index = (rng.next_u32() % (len as u32 - 5)) as usize;
                let mut payload = vec![0u8; len];
                rng.fill_bytes(&mut payload);
                let signature: Signature = signing_key.sign(&payload);
                let signature = signature.to_der().as_bytes().to_vec();
                let len = signature.len();
                let passkey = PassKey::new(
                    format!("{i}_{j}_{len}__ed25519"),
                    0,
                    BrowserInfo::default(),
                    -7,
                    spki.clone(),
                )
                .unwrap();
                assert!(passkey.verify(&signature, &payload[..index], &payload[index..]));
            }
        }
    }
}
