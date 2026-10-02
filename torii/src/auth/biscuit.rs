use std::{
    fs,
    io::{ErrorKind, Write},
    os::unix::fs::OpenOptionsExt,
};

use biscuit_auth::{KeyPair, format::schema::public_key::Algorithm};

use crate::error::Error;

pub fn generate_or_load_keypair(key_path: &String) -> Result<KeyPair, Error> {
    match fs::read(&key_path) {
        Ok(bytes) => Ok(KeyPair::from_bytes(&bytes, Algorithm::Ed25519)?),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let keypair = KeyPair::new();
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(key_path)?;
            file.write_all(&keypair.private().to_bytes())?;
            Ok(keypair)
        }
        Err(e) => Err(Error::from(e)),
    }
}
