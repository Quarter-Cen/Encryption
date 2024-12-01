extern crate ecdsa;
extern crate sha2;
extern crate rand;
extern crate k256;
extern crate hex;

use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use k256::ecdsa::SigningKey;
use ecdsa::signature::{Signer, Verifier};
use std::thread;
use std::sync::{Arc, Mutex};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

const CHUNK_SIZE: usize = 1 * 1024 * 1024; // 1 MB

fn main() {
    // สร้างคีย์ส่วนตัว (Private Key) และคีย์สาธารณะ (Public Key) สำหรับ sender
    let sender_private_key = SigningKey::random(&mut OsRng);
    let sender_public_key = sender_private_key.verifying_key(); // สร้าง VerifyingKey ของ sender

    // อ่านไฟล์
    let file_path = "Portfolio.pdf";
    let file = File::open(file_path).expect("Failed to open the file");

    // คำนวณจำนวน chunk ที่จะต้องแบ่งไฟล์ออกเป็น 1 MB ต่อ chunk
    let file_size = file.metadata().expect("Unable to read file metadata").len() as usize;
    let num_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;

    // ใช้ Arc และ Mutex สำหรับแชร์ข้อมูลระหว่าง thread
    let result = Arc::new(Mutex::new(Vec::new()));

    let start_time = Instant::now();

    //ที่เก็บ Thread
    let mut handles = vec![];

    for i in 0..num_chunks {
        let result = Arc::clone(&result);
        let mut file = file.try_clone().expect("Failed to clone the file");

        // คำนวณตำแหน่งของ chunk ในไฟล์
        let start = i * CHUNK_SIZE;
        let end = std::cmp::min(start + CHUNK_SIZE, file_size);

        // สร้าง thread และคำนวณแฮช
        let handle = thread::spawn(move || {
            // เลื่อน pointer ไปยังตำแหน่งที่เริ่มต้นของ chunk
            file.seek(SeekFrom::Start(start as u64)).expect("Failed to seek file");

            // อ่านข้อมูล chunk
            let mut buffer = vec![0u8; end - start];
            match file.read(&mut buffer) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        println!("Warning: Reached end of file, no more data to read.");
                        return;
                    }
                    buffer.truncate(bytes_read); // ปรับขนาดของ buffer ให้ตรงกับข้อมูลที่อ่าน

                    // สร้างแฮชของ chunk
                    let mut hasher = Sha256::new();
                    hasher.update(buffer);
                    let partial_hash = hasher.finalize();

                    // เอาผลลัพธ์เก็บไว้ใน Arc<Mutex> เพื่อแชร์ข้อมูล
                    let mut result = result.lock().unwrap();
                    result.push(partial_hash);
                }
                Err(e) => {
                    eprintln!("Failed to read file chunk: {}", e);
                    return;
                }
            }
        });
        handles.push(handle);
    }

    // รอให้ทุก thread เสร็จสิ้น
    for handle in handles {
        handle.join().unwrap();
    }


    let elapsed_time = start_time.elapsed();

    // รวมผลลัพธ์แฮชจากแต่ละส่วนเพื่อให้ได้แฮชสุดท้าย
    let result = result.lock().unwrap();
    let final_hash = result.iter().fold(Sha256::new(), |mut hasher, &hash| {
        hasher.update(hash);
        hasher
    }).finalize();

    // สร้างลายเซ็นดิจิทัลที่เซ็นจาก ข้อความ + sender_private_key
    let signature: ecdsa::Signature<k256::Secp256k1> = sender_private_key.try_sign(&final_hash).expect("Failed to sign the file");

    // แปลง Public Key ของ sender เป็น Hexadecimal String
    let sender_public_key_bytes = sender_public_key.to_sec1_bytes();
    let sender_public_key_hex = hex::encode(sender_public_key_bytes); // แปลงเป็น String ในรูปแบบ Hex

    // แสดงผลลายเซ็น
    println!("Signature: {:?}", signature);
    println!("Public Key of Sender: {}", sender_public_key_hex);

    // ตรวจสอบลายเซ็นโดยใช้ Public Key ของ sender
    match sender_public_key.verify(&final_hash, &signature) {
        Ok(_) => println!("Receiver: The signature is valid, the file is authentic."),
        Err(_) => println!("Receiver: The signature is invalid, the file is not authentic."),
    }

    // แสดงเวลาที่ใช้ในการประมวลผล
    println!("Time taken for file processing and signing: {:?}", elapsed_time);
}
