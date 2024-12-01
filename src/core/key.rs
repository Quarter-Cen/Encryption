use k256::ecdsa::{SigningKey, VerifyingKey}; // ใช้ VerifyingKey ให้ตรงกับประเภท

pub fn generate_keys() -> (SigningKey, VerifyingKey) {
    let private_key = SigningKey::random(&mut rand::rngs::OsRng);  // สร้าง SigningKey
    let public_key = private_key.verifying_key().clone();  // สร้าง VerifyingKey จาก SigningKey และ clone เพื่อให้เป็น owned value
    (private_key, public_key)  // คืนค่าทั้งสอง
}


pub fn public_key_to_hex(public_key: &VerifyingKey) -> String {
    hex::encode(public_key.to_sec1_bytes())  // แปลง public key เป็น hexadecimal string
}
