use encryption::core::hashing::{compute_file_hash, compute_data_hash};
use encryption::core::key::{generate_keys, public_key_to_hex, hex_to_public_key};
use encryption::core::signature::{sign_hash, verify_signature};
use encryption::core::utils::{create_nonce, get_current_timestamp};
use encryption::core::metadata::{check_secret, add_secret, create_doc, save_doc};

fn main() {
    let file_path = "Portfolio.pdf";

    let mut doc = create_doc(file_path);

    // สร้างคีย์ส่วนตัวและคีย์สาธารณะ
    let (private_key, public_key) = generate_keys();

    // แปลง Public Key เป็น Hex
    let public_key_hex = public_key_to_hex(&public_key);

    // สร้าง Nonce และ Timestamp
    let nonce = create_nonce();
    let timestamp = get_current_timestamp();

    // คำนวณแฮชของ Nonce และ Timestamp
    let nonce_hash = compute_data_hash(nonce.as_bytes()).expect("Failed to hash nonce");
    let timestamp_hash = compute_data_hash(&timestamp.to_be_bytes()).expect("Failed to hash timestamp");

    // ให้เพิ่ม nonce_hash ลงฐานข้อมูลก่อนนำไปเซ็น

    // เซ็นแฮชของ Nonce ด้วยคีย์ส่วนตัว
    let nonce_signature = sign_hash(&private_key, &nonce_hash);
    let nonce_signature_hash = compute_data_hash(&nonce_signature.to_bytes()).expect("Failed to hash nonce");


    // // เรียกฟังก์ชันเพิ่ม Info dictionary
    if let Err(e) = add_secret(&mut doc,&nonce_signature_hash,&timestamp_hash,&public_key) {
        println!("Error adding Info: {:?}", e);
    }

    save_doc(&mut doc, file_path);

    // คำนวณแฮชของไฟล์
    let file_hash = compute_file_hash(file_path).expect("Failed to compute file hash");

    // รวมข้อมูลทั้งหมดเพื่อคำนวณ hash
    let combined_metadata = [
        file_hash,
        nonce_signature_hash,
        timestamp_hash.clone(),
        public_key_hex.as_bytes().to_vec(),
    ].concat();
    let combined_hash = compute_data_hash(&combined_metadata).expect("Failed to combine hash");

    // เซ็นแฮชด้วยคีย์ส่วนตัว
    let signature = sign_hash(&private_key, &combined_hash);

    println!("Signature: {:?}", signature);
    println!("Public Key of Sender: {}", public_key_hex);
    println!("Nonce Hash: {:?}", nonce_hash);
    println!("Timestamp Hash: {:?}", timestamp_hash);


    let public_key_encode = hex_to_public_key(&public_key_hex);

    // ตรวจสอบลายเซ็นการส่ง
    if verify_signature(&public_key_encode, &combined_hash, &signature) {
        println!("Receiver: The signature is valid, the file is authentic.");
    } else {
        println!("Receiver: The signature is invalid, the file is not authentic.");
    }

    // ตรวจสอบลายเซ็น nonce
    if verify_signature(&public_key_encode, &nonce_hash, &nonce_signature) {
        println!("Receiver: The nonce is valid, the file is authentic.");
    } else {
        println!("Receiver: The nonce is invalid, the file is not authentic.");
    }

    // เรียกฟังก์ชันตรวจสอบ Info dictionary
    if let Err(e) = check_secret(&doc) {
            println!("Error checking Info: {:?}", e);
    }
}
