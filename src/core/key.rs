use k256::ecdsa::{SigningKey, VerifyingKey};

pub fn generate_keys() -> (SigningKey, VerifyingKey) {
    let private_key = SigningKey::random(&mut rand::rngs::OsRng);
    let public_key = private_key.verifying_key().clone();
    (private_key, public_key)
}


pub fn public_key_to_hex(public_key: &VerifyingKey) -> String {
    hex::encode(public_key.to_sec1_bytes())  // แปลง public key เป็น hexadecimal string
}