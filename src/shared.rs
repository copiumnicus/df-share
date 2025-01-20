use ring::{
    agreement::{agree_ephemeral, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, ECDH_P256},
    error::Unspecified,
    hkdf::{self, Salt},
    rand::SystemRandom,
};

pub(crate) mod bytes_hex {
    //! Serialization of Vec<u8> to 0x prefixed hex string
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    use std::borrow::Cow;

    pub fn serialize<S, T>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        serializer.serialize_str(&crate::to_hex_str(bytes.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let prefixed_hex_str = Cow::<str>::deserialize(deserializer)?;
        crate::from_hex_str(&prefixed_hex_str).ok_or(D::Error::custom("fail deser hex str"))
    }
}

pub(crate) struct EphemeralKeyPair {
    pub _pk: EphemeralPrivateKey,
    pub pubk: PublicKey,
}

impl EphemeralKeyPair {
    pub(crate) fn new() -> Result<Self, Unspecified> {
        let rng = SystemRandom::new();
        let pk = EphemeralPrivateKey::generate(&ECDH_P256, &rng)?;
        let pubk = pk.compute_public_key()?;
        Ok(Self { _pk: pk, pubk })
    }
}

pub(crate) fn ecdh_compute_shared_secret(
    my_private_key: EphemeralPrivateKey,
    peer_public_key: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let peer_pub = UnparsedPublicKey::new(&ECDH_P256, peer_public_key);
    agree_ephemeral(my_private_key, &peer_pub, Unspecified, |shared| {
        Ok(shared.to_vec())
    })
}

/// Derive a 256-bit AES key using HKDF-SHA256. Return AES key.
pub(crate) fn derive_aes_key(salt_bytes: [u8; 16], shared_secret: &[u8]) -> [u8; 32] {
    let salt = Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(shared_secret);

    let info = b"copiumnicus df-share rust";
    let infos = [info.as_slice()];
    let okm = prk
        .expand(infos.as_slice(), hkdf::HKDF_SHA256)
        .expect("HKDF expand failed");

    let mut aes_key = [0u8; 32];
    okm.fill(&mut aes_key).expect("HKDF fill failed");
    aes_key
}

pub fn to_hex_str(v: &[u8]) -> String {
    format!(
        "0x{}",
        v.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
            .to_string()
    )
}
pub fn from_hex_str(mut s: &str) -> Option<Vec<u8>> {
    if s.starts_with("0x") {
        s = &s[2..]
    }
    if s.len() % 2 != 0 {
        return None;
    }
    Some(
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect(),
    )
}
