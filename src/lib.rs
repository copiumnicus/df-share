//! # df-share: Secret Sharing
//!
//! This module provides a straightforward API to securely exchange a secret between two parties (a client and a server) using ephemeral Diffie-Hellman keys.
//! The server encrypts the secret in such a way that only the requesting client can decrypt it, assuming both sides derive the same shared secret key.
//!
//! ## Basic Usage
//!
//! 1. **Client creates an ephemeral key pair** via [`EphemeralClient::new()`].
//!    - Call [`EphemeralClient::sendable()`] to retrieve a tuple: a request object and a `decryptor`.
//! 2. **Server receives the request**, creates its own ephemeral key pair via [`EphemeralServer::new()`], and calls [`EphemeralServer::encrypt_secret()`] to produce a response containing the encrypted secret.
//! 3. **Client decrypts the response** with the `decryptor` it previously obtained.
//!
//! ### Example
//!
//! ```rust
//! use df_share::{EphemeralClient, EphemeralServer};
//! use df_share::error::Unspecified;
//! # fn example() -> Result<(), Unspecified> {
//! // Client side
//! let client = EphemeralClient::new()?;
//! let (req, decryptor) = client.sendable();
//!
//! let res;
//! let secret = "MyVerySecretPrivateKey010101010";
//!
//! // Server side
//! {
//!     let server = EphemeralServer::new()?;
//!     res = server.encrypt_secret(&req, secret.as_bytes())?;
//! }
//!
//! // Client side again: decrypt the server's response
//! let decrypted_secret = decryptor.decrypt(&res)?;
//!
//! assert_eq!(secret.as_bytes(), &decrypted_secret);
//! # Ok(())
//! # }
//! ```
//!
//! **Important Note**: Because the server generates an ephemeral key pair each time, there's no built-in guarantee of the server's identity. If you need server authentication, you must maintain long-term server key material and pin the server public key on the client or use HTTPS/TLS with certificate validation.
mod client;
mod server;
pub(crate) mod shared;

// api
pub use client::{ClientReq, EphemeralClient, ResponseDecryptor};
pub use server::{EphemeralServer, ServerEncryptedRes};
// re-export ring error
pub mod error {
    pub use ring::error::Unspecified;
}
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
