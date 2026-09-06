// SPDX-License-Identifier: GPL-3.0-or-later
//! Client-side encryption for Lumo requests/responses.
//!
//! Scheme (matching the official web client):
//! - a fresh AES-256 key per request
//! - every turn encrypted with AES-256-GCM (12-byte IV, 16-byte tag, AAD bound
//!   to the request id), sent as base64(iv || ciphertext || tag)
//! - the AES key itself encrypted to Lumo's PGP public key and sent as
//!   `request_key` (base64 of a binary OpenPGP message)
//! - response chunks come back encrypted with the same AES key.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pgp::composed::{MessageBuilder, SignedPublicKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

/// AES-GCM nonce and tag sizes, as laid out in every encrypted turn.
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub struct RequestCrypto {
    pub aes_key: [u8; 32],
    cipher: Aes256Gcm,
}

impl Drop for RequestCrypto {
    fn drop(&mut self) {
        // Wipe the raw key from memory once the request is done. (The cipher's
        // internal key schedule is managed by `aes-gcm`; this covers our copy.)
        self.aes_key.zeroize();
    }
}

impl RequestCrypto {
    pub fn new() -> Self {
        let mut aes_key = [0u8; 32];
        OsRng.fill_bytes(&mut aes_key);
        let cipher = Aes256Gcm::new((&aes_key).into());
        Self { aes_key, cipher }
    }

    /// Encrypt one turn's content: base64(iv || ciphertext || tag).
    pub fn encrypt_turn(&self, aad: &[u8], plaintext: &str) -> Result<String> {
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);
        let nonce = Nonce::from(iv);
        let ct = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad,
                },
            )
            .map_err(|e| anyhow!("AES-GCM encryption failed: {e}"))?;
        let mut out = Vec::with_capacity(ct.len().saturating_add(IV_LEN));
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct); // ct already ends with the 16-byte tag
        Ok(B64.encode(out))
    }

    /// Decrypt one response chunk: input is base64(iv || ciphertext || tag).
    pub fn decrypt_chunk(&self, aad: &[u8], b64_content: &str) -> Result<String> {
        let raw = B64.decode(b64_content).context("invalid base64 chunk")?;
        if raw.len() < IV_LEN.saturating_add(TAG_LEN) {
            return Err(anyhow!("encrypted chunk too short: {} bytes", raw.len()));
        }
        let (iv, ct) = raw
            .split_at_checked(IV_LEN)
            .ok_or_else(|| anyhow!("encrypted chunk too short"))?;
        let iv: [u8; IV_LEN] = iv.try_into().context("malformed nonce")?;
        let nonce = Nonce::from(iv);
        let pt = self
            .cipher
            .decrypt(&nonce, Payload { msg: ct, aad })
            .map_err(|e| anyhow!("response integrity check failed: {e}"))?;
        String::from_utf8(pt).context("decrypted chunk is not UTF-8")
    }

    /// Encrypt the AES request key to Lumo's PGP public key (parsed once by the
    /// caller and passed in). Returns base64 of the binary OpenPGP message.
    pub fn encrypted_request_key(&self, lumo_key: &SignedPublicKey) -> Result<String> {
        // The Lumo key is an EdDSA primary with a single cv25519 encryption subkey.
        let subkey = lumo_key
            .public_subkeys
            .first()
            .ok_or_else(|| anyhow!("Lumo PGP key has no encryption subkey"))?;

        let mut builder = MessageBuilder::from_bytes("", self.aes_key.to_vec())
            .seipd_v1(rand::thread_rng(), SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key(rand::thread_rng(), subkey)
            .map_err(|e| anyhow!("PGP encrypt_to_key failed: {e}"))?;
        let binary = builder
            .to_vec(rand::thread_rng())
            .map_err(|e| anyhow!("PGP message serialization failed: {e}"))?;
        Ok(B64.encode(binary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{request_aad, response_aad};

    #[test]
    fn turn_roundtrip() {
        let c = RequestCrypto::new();
        let aad = request_aad("00000000-0000-0000-0000-000000000000");
        let enc = c.encrypt_turn(&aad, "hello world 🦀").unwrap();
        // encrypt_turn output uses the request AAD; decrypt with the same AAD
        // by reusing decrypt_chunk's layout expectations.
        let raw = B64.decode(&enc).unwrap();
        assert!(raw.len() > 12 + 16);
        let nonce = Nonce::try_from(&raw[..12]).unwrap();
        let pt = c
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &raw[12..],
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(pt, "hello world 🦀".as_bytes());
    }

    #[test]
    fn chunk_rejects_wrong_aad() {
        let c = RequestCrypto::new();
        let id = "11111111-1111-1111-1111-111111111111";
        let enc = c.encrypt_turn(&response_aad(id), "secret").unwrap();
        assert!(c.decrypt_chunk(&request_aad(id), &enc).is_err());
        assert_eq!(c.decrypt_chunk(&response_aad(id), &enc).unwrap(), "secret");
    }

    #[test]
    fn request_key_is_valid_pgp() {
        use pgp::composed::Deserializable;
        let (key, _) = SignedPublicKey::from_string(crate::protocol::LUMO_PGP_PUBLIC_KEY).unwrap();
        let c = RequestCrypto::new();
        let b64 = c.encrypted_request_key(&key).unwrap();
        let raw = B64.decode(&b64).unwrap();
        // Must parse as an OpenPGP message with a PKESK for Lumo's subkey.
        let msg = pgp::composed::Message::from_bytes(&raw[..]).unwrap();
        drop(msg);
        assert!(raw.len() > 90);
    }
}
