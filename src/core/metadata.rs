use lopdf::{Document, Object, Dictionary};
use std::{fs::File, str};
use k256::ecdsa::VerifyingKey;
use super::key::public_key_to_hex;

pub fn create_doc(file_path: &str) -> Document {
    Document::load(file_path).expect("Failed to load the document")
}

pub fn save_doc(doc:&mut Document, file_path: &str) -> File {
    doc.save(file_path).expect("Failed to save the document")
}

pub fn check_secret(doc: &Document) -> Result<(), Box<dyn std::error::Error>> {
    let info_ref = doc.trailer.get(b"Secret");
    if let Ok(Object::Reference((id, generation))) = info_ref {
        let info = doc.get_object((*id, *generation))?;
        if let Object::Dictionary(info_dict) = info {
            if info_dict.is_empty() {
                println!("Info dictionary is empty.");
            } else {
                println!("Existing Info dictionary:");
                for (key, value) in info_dict {
                    let key_str = str::from_utf8(&key).unwrap_or("<Invalid UTF-8>");
                    println!("{}: {:?}", key_str, value);
                }
            }
        } else {
            println!("Info object is not a dictionary.");
        }
    } else {
        println!("Info reference not found.");
    }
    Ok(())
}

/// เพิ่มข้อมูลใน Info Dictionary
pub fn add_secret(doc: &mut Document, nonce_signature_hash: &Vec<u8>, timestamp_hash: &Vec<u8>, public_key: &VerifyingKey) -> Result<(), Box<dyn std::error::Error>> {
    let mut info_dict = Dictionary::new();
    info_dict.set("Nonce Signature Hash", Object::string_literal(nonce_signature_hash.clone()));
    info_dict.set("Timestamp Hash", Object::string_literal(timestamp_hash.clone()));
    info_dict.set("Public Key", Object::string_literal(public_key_to_hex(&public_key)));

    // เพิ่ม Info dictionary ใหม่ในไฟล์ PDF
    let info_id = doc.add_object(info_dict);
    doc.trailer.set("Secret", Object::Reference(info_id));

    println!("New Info dictionary added.");
    Ok(())
}