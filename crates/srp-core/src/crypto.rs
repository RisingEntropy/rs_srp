//! Password-based key derivation for the Noise PSK.

use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};

/// Fixed application salt. The password is the real secret; this salt only
/// provides domain separation, and both peers must derive an identical key, so
/// a constant is correct here.
const PSK_SALT: &[u8] = b"rs_srp/noise-psk/v1";

/// Derive the 32-byte Noise PSK from the shared password with Argon2id.
///
/// The parameters are deliberately expensive (64 MiB, 3 passes) so that a
/// captured handshake is costly to brute-force offline.
pub fn derive_psk(password: &str) -> Result<[u8; 32]> {
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut psk = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), PSK_SALT, &mut psk)
        .map_err(|e| anyhow::anyhow!("argon2 derivation: {e}"))?;
    Ok(psk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_is_deterministic_and_password_dependent() {
        let a = derive_psk("hunter2").unwrap();
        let b = derive_psk("hunter2").unwrap();
        let c = derive_psk("hunter3").unwrap();
        assert_eq!(a, b, "same password must yield the same PSK");
        assert_ne!(a, c, "different passwords must yield different PSKs");
    }
}
