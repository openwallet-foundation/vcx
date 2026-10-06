use askar_crypto::{
    alg::{AnyKey, AnyKeyCreate, KeyAlg},
    repr::ToPublicBytes,
};

use crate::{Key, KeyType, PublicKeyError};

impl Key {
    pub fn derive_x25519(&self) -> Result<Self, PublicKeyError> {
        if self.key_type() != &KeyType::Ed25519 {
            return Err(PublicKeyError::InvalidKeyType(
                *self.key_type(),
                KeyType::Ed25519,
            ));
        }

        let ed25519_key: Box<AnyKey> = AnyKeyCreate::from_public_bytes(KeyAlg::Ed25519, self.key())
            .map_err(|error| PublicKeyError::UnsupportedKeyType(error.to_string()))?;
        let x25519_key = ed25519_key
            .convert_key(KeyAlg::X25519)
            .map_err(|error| PublicKeyError::UnsupportedKeyType(error.to_string()))?;
        let public_key = x25519_key
            .to_public_bytes()
            .map_err(|error| PublicKeyError::UnsupportedKeyType(error.to_string()))?
            .to_vec();

        Ok(Key::from_raw_bytes(public_key, KeyType::X25519))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_FINGERPRINT: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const X25519_FINGERPRINT: &str = "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p";
    const P256_FINGERPRINT: &str = "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";

    #[test]
    fn raw_x25519_key_preserves_multicodec_like_prefix() {
        let mut raw_key = vec![0xec, 0x01];
        raw_key.extend([0; 30]);

        let key = Key::from_raw_bytes(raw_key.clone(), KeyType::X25519);

        assert_eq!(key.key(), raw_key);
        assert_eq!(Key::from_fingerprint(&key.fingerprint()).unwrap(), key);
    }

    #[test]
    fn derives_x25519_from_official_ed25519_vector() {
        let ed25519_key = Key::from_fingerprint(ED25519_FINGERPRINT).unwrap();

        let x25519_key = ed25519_key.derive_x25519().unwrap();

        assert_eq!(x25519_key.fingerprint(), X25519_FINGERPRINT);
    }

    #[test]
    fn derived_key_has_x25519_type() {
        let ed25519_key = Key::from_fingerprint(ED25519_FINGERPRINT).unwrap();

        let x25519_key = ed25519_key.derive_x25519().unwrap();

        assert_eq!(x25519_key.key_type(), &KeyType::X25519);
    }

    #[test]
    fn rejects_non_ed25519_keys() {
        let p256_key = Key::from_fingerprint(P256_FINGERPRINT).unwrap();

        let result = p256_key.derive_x25519();

        assert!(matches!(
            result,
            Err(PublicKeyError::InvalidKeyType(
                KeyType::P256,
                KeyType::Ed25519
            ))
        ));
    }
}
