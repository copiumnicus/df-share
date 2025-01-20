use df_share::error::Unspecified;
use df_share::*;
use std::collections::HashSet;

fn main() -> Result<(), Unspecified> {
    let secrets: Vec<String> = (1..=100).map(|i| format!("SuperSecret #{}", i)).collect();

    let mut nonce_set = HashSet::new();
    let mut salt_set = HashSet::new();
    let mut pubk_set = HashSet::new();
    let mut client_pubk_set = HashSet::new();
    for (_, secret) in secrets.iter().enumerate() {
        let client = EphemeralClient::new()?;
        let (req, decryptor) = client.sendable();

        let server = EphemeralServer::new()?;
        let res = server.encrypt_secret(&req, secret.as_bytes())?;

        let decrypted_secret = decryptor.decrypt(&res)?;

        // sanity

        assert!(secret.as_bytes() != res.ciphertext);
        assert!(secret.as_bytes() == &decrypted_secret);

        // assert non repeatable

        assert!(!nonce_set.contains(&res.nonce));
        nonce_set.insert(res.nonce);
        assert!(!salt_set.contains(&res.salt));
        salt_set.insert(res.salt);
        assert!(!pubk_set.contains(&res.pubk));
        pubk_set.insert(res.pubk.clone());
        assert!(!client_pubk_set.contains(&req.pubk));
        client_pubk_set.insert(req.pubk.clone());

        // print to see how these things look
        println!(
            "{} REQ:\n{}\nRES:\n{}\n",
            secret,
            serde_json::to_string_pretty(&req).unwrap(),
            serde_json::to_string_pretty(&res).unwrap()
        );
    }

    Ok(())
}
