/// AES-256-GCM wire-compatible with Go/Nim server.
/// Wire format: nonce(12) || ciphertext || tag(16)
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

pub fn random_bytes(buf: &mut [u8]) {
    unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        );
    }
}

/// Encrypt plaintext → nonce(12) || ciphertext || tag(16)
pub fn seal(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    random_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    // aes-gcm::encrypt returns ciphertext || tag(16)
    let ct = cipher.encrypt(nonce, plaintext).unwrap_or_default();
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ct);
    out
}

/// Decrypt nonce(12) || ciphertext || tag(16) → plaintext
pub fn open(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 + 16 {
        return None;
    }
    let (nonce_bytes, ct) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, ct).ok()
}
