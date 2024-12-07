use k256::ecdsa::{SigningKey, VerifyingKey};

pub fn generate_keys() -> (SigningKey, VerifyingKey) {
    let private_key = SigningKey::random(&mut rand::rngs::OsRng);
    let public_key = private_key.verifying_key().clone();
    (private_key, public_key)
}


pub fn public_key_to_hex(public_key: &VerifyingKey) -> String {
    hex::encode(public_key.to_sec1_bytes())  // แปลง public key เป็น hexadecimal string
}

pub fn hex_to_public_key(hex_string: &str) -> VerifyingKey {
    // แปลงจาก hexadecimal string เป็น Vec<u8>
    let bytes = hex::decode(hex_string).unwrap();  // ใช้ unwrap เพื่อจัดการข้อผิดพลาด
    
    // แปลง Vec<u8> กลับเป็น VerifyingKey
    let public_key = VerifyingKey::from_sec1_bytes(&bytes).unwrap();  // ใช้ unwrap เพื่อลบ Result

    public_key
}