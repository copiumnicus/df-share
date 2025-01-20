mod client;
mod server;
pub(crate) mod shared;

// api
pub use client::{ClientReq, EphemeralClient, ResponseDecryptor};
pub use server::{EphemeralServer, ServerEncryptedRes};
// re-export ring error
pub use ring::error::Unspecified;
// utility
pub use shared::{from_hex_str, to_hex_str};

#[cfg(test)]
mod test {
    use super::*;
    use client::EphemeralClient;
    use ring::error::Unspecified;
    use server::EphemeralServer;

    #[test]
    fn test_share_secret() -> Result<(), Unspecified> {
        // client side
        let client = EphemeralClient::new()?;
        let (req, decryptor) = client.sendable();

        let res;
        let secret = "MyVerySecretPrivateKey";
        {
            // server side
            let server = EphemeralServer::new()?;
            res = server.encrypt_secret(&req, secret.as_bytes())?;
        }

        // client side
        let decrypted_secret = decryptor.decrypt(&res)?;

        assert_eq!(secret.as_bytes(), &decrypted_secret);
        assert!(decrypted_secret != res.ciphertext);
        Ok(())
    }
}
