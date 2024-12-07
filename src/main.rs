use encryption::core::hashing::{compute_file_hash, compute_data_hash};
use encryption::core::key::{generate_keys, public_key_to_hex};
use encryption::core::signature::{sign_hash, verify_signature};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn main() {
    let file_path = "Portfolio.pdf";

    // สร้างคีย์ส่วนตัวและคีย์สาธารณะ
    let (private_key, public_key) = generate_keys();

    // แปลง Public Key เป็น Hex
    let public_key_hex = public_key_to_hex(&public_key);

    // คำนวณแฮชของไฟล์
    let start_time = Instant::now();
    let file_hash = compute_file_hash(file_path).expect("Failed to compute file hash");
    let elapsed_time = start_time.elapsed();

    // สร้าง Nonce และ Timestamp
    let nonce = "random_nonce";
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();

    // คำนวณแฮชของ Nonce และ Timestamp
    let nonce_hash = compute_data_hash(nonce.as_bytes()).expect("Failed to hash nonce");
    let timestamp_hash = compute_data_hash(&timestamp.to_be_bytes()).expect("Failed to hash timestamp");

    // ให้เพิ่ม nonce_hash ลงฐานข้อมูลก่อนนำไปเซ็น

    // เซ็นแฮชของ Nonce ด้วยคีย์ส่วนตัว
    let nonce_signature = sign_hash(&private_key, &nonce_hash);
    let nonce_signature_hash = compute_data_hash(&nonce_signature.to_bytes()).expect("Failed to hash nonce");

    // รวมข้อมูลทั้งหมดเพื่อคำนวณ hash
    let combined_metadata = [
        file_hash,
        nonce_signature_hash,
        timestamp_hash.clone(),
        public_key_hex.as_bytes().to_vec(),
    ].concat();
    let combined_hash = compute_data_hash(&combined_metadata).expect("Failed to combine hash");

    let start_sign_time = Instant::now();
    // เซ็นแฮชด้วยคีย์ส่วนตัว
    let signature = sign_hash(&private_key, &combined_hash);
    let elapsed_sign_time = start_sign_time.elapsed();


    println!("Signature: {:?}", signature);
    println!("Public Key of Sender: {}", public_key_hex);
    println!("Nonce Hash: {:?}", nonce_hash);
    println!("Timestamp Hash: {:?}", timestamp_hash);

    let start_verify_time = Instant::now();

    // ตรวจสอบลายเซ็นการส่ง
    if verify_signature(&public_key, &combined_hash, &signature) {
        println!("Receiver: The signature is valid, the file is authentic.");
    } else {
        println!("Receiver: The signature is invalid, the file is not authentic.");
    }

    // ตรวจสอบลายเซ็น nonce
    if verify_signature(&public_key, &nonce_hash, &nonce_signature) {
        println!("Receiver: The nonce is valid, the file is authentic.");
    } else {
        println!("Receiver: The nonce is invalid, the file is not authentic.");
    }

    let elapsed_verify_time = start_verify_time.elapsed();

    println!("Time taken for file hashing: {:?}", elapsed_time);
    println!("Time taken for file signing: {:?}", elapsed_sign_time);
    println!("Time taken for file verifying: {:?}", elapsed_verify_time);
    
}
