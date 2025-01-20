# df-share

**df-share** is a lightweight helper library for one-off (ephemeral) Diffie-Hellman exchanges that let a server encrypt a secret so **only** the requesting client can decrypt it. The server uses a freshly generated key pair for **each** request, returning `(encrypted_secret, server_pubk, nonce, salt)`. The client then uses the corresponding ephemeral keys on its side to derive the shared secret and decrypt.

## Trade-offs

- This implementation **does not** authenticate the server’s identity. Any party could impersonate the server. If you need to verify you’re talking to the _real_ server, you should:
  - Maintain a long-lived key pair on the server side.
  - Pin the server’s public key on the clients (or otherwise authenticate it).
- In this ephemeral approach, there’s no persistent server key material. That means:
  - **Pro**: Each exchange uses new keys, enhancing forward secrecy.
  - **Con**: You lose server identity guarantees out of the box.

## Example Usage

```rust
// Client side
let client = EphemeralClient::new().unwrap();
let (req, decryptor) = client.sendable();

// The client sends `req` (which includes its ephemeral public key)
// to the server. Then the server encrypts the secret:

let res;
let secret = "MyVerySecretPrivateKey";
{
    // Server side
    let server = EphemeralServer::new().unwrap();
    res = server.encrypt_secret(&req, secret.as_bytes()).unwrap();
}

// Back on the client side, we decrypt using the matching ephemeral keys:
let decrypted_secret = decryptor.decrypt(&res).unwrap();

assert_eq!(secret.as_bytes(), &decrypted_secret);
// Confirm the ciphertext differs from the secret:
assert!(decrypted_secret != res.ciphertext);
```

In this snippet:

1. The **client** creates an ephemeral key pair and prepares a `req` message.
2. The **server** generates its own ephemeral key pair, derives the shared secret with the client’s `req`, and encrypts the actual `secret`.
3. The **client** applies its matching ephemeral private key to derive the same shared secret and decrypt the server’s response.

Use **df-share** to keep your secret data private between two parties, as long as you’re operating over a trusted channel (e.g., HTTPS) or have other means to ensure the server is who you expect.
