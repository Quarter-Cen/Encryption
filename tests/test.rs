use encryption::core::hashing::compute_file_hash;
use encryption::core::key::{generate_keys, public_key_to_hex};
use encryption::core::signature::{sign_hash, verify_signature};

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compute_file_hash() {
        let mut tmp_file = NamedTempFile::new().expect("Failed to create temporary file");

        // เขียนข้อมูลทดสอบลงในไฟล์
        tmp_file
            .write_all(b"Hello, this is a test file!")
            .expect("Failed to write to temporary file");

        let result = compute_file_hash(tmp_file.path().to_str().unwrap());

        // ตรวจสอบผลลัพธ์
        assert!(result.is_ok(), "Expected Ok result, but got {:?}", result);
        let hash = result.unwrap();

        assert!(!hash.is_empty(), "Hash should not be empty");
    }

    #[test]
    fn test_empty_file_hash() {
        let tmp_file = NamedTempFile::new().expect("Failed to create temporary file");

        let result = compute_file_hash(tmp_file.path().to_str().unwrap());

        assert!(result.is_ok(), "Expected Ok result, but got {:?}", result);
        let hash = result.unwrap();

        assert!(!hash.is_empty(), "Hash should not be empty");
    }

    #[test]
    fn test_file_hash_with_large_data() {
        let mut tmp_file = NamedTempFile::new().expect("Failed to create temporary file");

        let large_data = vec![0u8; 10 * 1024 * 1024]; // 10MB
        tmp_file
            .write_all(&large_data)
            .expect("Failed to write to temporary file");

        let result = compute_file_hash(tmp_file.path().to_str().unwrap());

        assert!(result.is_ok(), "Expected Ok result, but got {:?}", result);
        let hash = result.unwrap();

        assert!(!hash.is_empty(), "Hash should not be empty");
    }

    #[test]
    fn test_generate_keys() {
        let (private_key, public_key) = generate_keys();

        // ตรวจสอบว่า private_key เป็น SigningKey
        assert!(
            private_key.to_bytes().len() > 0,
            "Private key should not be empty"
        );

        // ตรวจสอบว่า public_key เป็น VerifyingKey
        assert!(
            public_key.to_sec1_bytes().len() > 0,
            "Public key should not be empty"
        );

        // ตรวจสอบว่าฟังก์ชัน generate_keys สามารถสร้างคีย์ได้ไม่เป็นค่าเริ่มต้น
        let (private_key_2, public_key_2) = generate_keys();
        assert!(
            private_key != private_key_2,
            "Private keys should be unique"
        );
        assert!(public_key != public_key_2, "Public keys should be unique");
    }

    #[test]
    fn test_public_key_to_hex() {

        let (_, public_key) = generate_keys();

        let hex_public_key = public_key_to_hex(&public_key);

        assert!(
            !hex_public_key.is_empty(),
            "Hex public key should not be empty"
        );

        assert!(
            hex_public_key.len() % 2 == 0,
            "Hex string should have an even number of characters"
        );

        println!("Public key in hex: {}", hex_public_key);
    }

    #[test]
    fn test_sign_hash() {
        // สร้าง SigningKey และ VerifyingKey
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        let public_key = signing_key.verifying_key();

        // สร้าง hash ตัวอย่าง (สมมุติ)
        let hash = b"example data to sign";

        // ใช้ฟังก์ชัน sign_hash เพื่อสร้างลายเซ็นต์
        let signature = sign_hash(&signing_key, hash);

        // ตรวจสอบว่า signature ไม่เป็นค่าว่าง
        assert!(
            !signature.to_bytes().is_empty(),
            "Signature should not be empty"
        );

        // ตรวจสอบว่า signature เป็นลายเซ็นต์ที่สามารถตรวจสอบได้
        assert!(
            verify_signature(&public_key, hash, &signature),
            "Signature should be valid"
        );
    }

    #[test]
    fn test_verify_signature_invalid() {
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        let public_key = signing_key.verifying_key();

        // สร้าง hash ตัวอย่าง
        let hash = b"example data to sign";

        // ใช้ฟังก์ชัน sign_hash เพื่อสร้างลายเซ็นต์
        let signature = sign_hash(&signing_key, hash);

        // สร้าง hash ที่ผิดพลาดเพื่อทดสอบการตรวจสอบลายเซ็นต์
        let invalid_hash = b"wrong data";

        // ทดสอบว่า signature ไม่ถูกต้องเมื่อใช้ hash ที่ผิด
        assert!(
            !verify_signature(&public_key, invalid_hash, &signature),
            "Signature should be invalid for incorrect data"
        );
    }
}
