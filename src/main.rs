use encryption::core::hashing::compute_file_hash;
use encryption::core::key::{generate_keys, public_key_to_hex};
use encryption::core::signature::{sign_hash, verify_signature};

use std::time::Instant;

fn main() {
    let file_path = "Portfolio.pdf";

    // สร้างคีย์ส่วนตัวและคีย์สาธารณะ
    let (private_key, public_key) = generate_keys();

    // คำนวณแฮชของไฟล์
    let start_time = Instant::now();
    let file_hash = compute_file_hash(file_path).expect("Failed to compute file hash");
    let elapsed_time = start_time.elapsed();

    // เซ็นแฮชด้วยคีย์ส่วนตัว
    let signature = sign_hash(&private_key, &file_hash);

    // แปลง Public Key เป็น Hex
    let public_key_hex = public_key_to_hex(&public_key);

    // แสดงผลลัพธ์
    println!("Signature: {:?}", signature);
    println!("Public Key of Sender: {}", public_key_hex);

    // ตรวจสอบลายเซ็น
    if verify_signature(&public_key, &file_hash, &signature) {
        println!("Receiver: The signature is valid, the file is authentic.");
    } else {
        println!("Receiver: The signature is invalid, the file is not authentic.");
    }

    println!("Time taken for file processing and signing: {:?}", elapsed_time);
}
