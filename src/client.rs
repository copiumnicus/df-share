use super::shared::{derive_aes_key, ecdh_compute_shared_secret, EphemeralKeyPair};
use crate::server::ServerEncryptedRes;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ring::agreement::EphemeralPrivateKey;
use ring::error::Unspecified;
use serde::{Deserialize, Serialize};

/// Generate per request. Do not reuse.
pub struct EphemeralClient {
    pair: EphemeralKeyPair,
}

impl EphemeralClient {
    pub fn new() -> Result<Self, Unspecified> {
        Ok(Self {
            pair: EphemeralKeyPair::new()?,
        })
    }
    pub fn sendable(self) -> (ClientReq, ResponseDecryptor) {
        (
            ClientReq {
                pubk: self.pair.pubk.as_ref().to_vec(),
            },
            ResponseDecryptor { _pk: self.pair._pk },
        )
    }
}

pub struct ResponseDecryptor {
    _pk: EphemeralPrivateKey,
}

impl ResponseDecryptor {
    pub fn decrypt(self, res: &ServerEncryptedRes) -> Result<Vec<u8>, Unspecified> {
        let shared_secret = ecdh_compute_shared_secret(self._pk, &res.pubk)?;
        let aes_key = derive_aes_key(res.salt, &shared_secret);
        Ok(aes_gcm_decrypt(&aes_key, &res.nonce, &res.ciphertext))
    }
}

/// Decrypt with AES-256-GCM.
fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .expect("AES-GCM decryption failed")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientReq {
    #[serde(with = "crate::shared::bytes_hex")]
    pub pubk: Vec<u8>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ser_client_pubk() {
        let client = ClientReq {
            pubk: vec![1, 2, 3],
        };
        let ser = serde_json::to_string(&client).unwrap();
        println!("{}", ser);
        let deser: ClientReq = serde_json::from_str(&ser).unwrap();
        assert_eq!(client.pubk, deser.pubk);
    }
}
