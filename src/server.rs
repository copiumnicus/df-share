use super::shared::{derive_aes_key, ecdh_compute_shared_secret, EphemeralKeyPair};
use crate::client::ClientReq;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use ring::error::Unspecified;
use serde::{Deserialize, Serialize};

/// Generate per request. Do not reuse.
pub struct EphemeralServer {
    pair: EphemeralKeyPair,
}

impl EphemeralServer {
    pub fn new() -> Result<Self, Unspecified> {
        Ok(Self {
            pair: EphemeralKeyPair::new()?,
        })
    }

    /// consume self to force not reusing keys
    pub fn encrypt_secret(
        self,
        req: &ClientReq,
        plaintext: &[u8],
    ) -> Result<ServerEncryptedRes, Unspecified> {
        let shared_secret = ecdh_compute_shared_secret(self.pair._pk, &req.pubk)?;

        // generate salt
        let mut salt_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt_bytes);

        let aes_key = derive_aes_key(salt_bytes, &shared_secret);

        // Generate a random 96-bit (12-byte) nonce for AES-GCM.
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let encrypted = aes_gcm_encrypt(&aes_key, &nonce, plaintext);

        Ok(ServerEncryptedRes {
            ciphertext: encrypted,
            nonce,
            salt: salt_bytes,
            pubk: self.pair.pubk.as_ref().to_vec(),
        })
    }
}

/// Encrypt with AES-256-GCM.
fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .expect("AES-GCM encryption failed")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerEncryptedRes {
    #[serde(with = "crate::shared::bytes_hex")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "crate::shared::bytes_hex")]
    pub pubk: Vec<u8>,
    #[serde(with = "hex_12")]
    pub nonce: [u8; 12],
    #[serde(with = "hex_16")]
    pub salt: [u8; 16],
}

mod hex_16 {
    use crate::{from_hex_str, to_hex_str};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&to_hex_str(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        let decoded = from_hex_str(&s).ok_or(serde::de::Error::custom("fail decode"))?;
        if decoded.len() != 16 {
            return Err(serde::de::Error::custom(format!(
                "expected 16 bytes, got {}",
                decoded.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}
mod hex_12 {
    use crate::{from_hex_str, to_hex_str};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 12], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&to_hex_str(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 12], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        let decoded = from_hex_str(&s).ok_or(serde::de::Error::custom("fail decode"))?;
        if decoded.len() != 12 {
            return Err(serde::de::Error::custom(format!(
                "expected 12 bytes, got {}",
                decoded.len()
            )));
        }
        let mut arr = [0u8; 12];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ser_server_res() {
        let res = ServerEncryptedRes {
            pubk: vec![1, 2, 3],
            ciphertext: vec![4, 5, 6],
            nonce: [1; 12],
            salt: [20; 16],
        };
        let ser = serde_json::to_string(&res).unwrap();
        println!("{}", ser);
        let deser: ServerEncryptedRes = serde_json::from_str(&ser).unwrap();
        assert_eq!(res.pubk, deser.pubk);
        assert_eq!(res.ciphertext, deser.ciphertext);
        assert_eq!(res.nonce, deser.nonce);
        assert_eq!(res.salt, deser.salt);
    }
}
