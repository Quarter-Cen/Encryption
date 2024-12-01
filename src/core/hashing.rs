use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;

const CHUNK_SIZE: usize = 1 * 1024 * 1024; // 1 MB

pub fn compute_file_hash(file_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len() as usize;
    let num_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;

    let result = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    for i in 0..num_chunks {
        let result = Arc::clone(&result);
        let mut file = file.try_clone()?;
        let start = i * CHUNK_SIZE;
        let end = std::cmp::min(start + CHUNK_SIZE, file_size);

        let handle = thread::spawn(move || {
            let mut buffer = vec![0u8; end - start];
            if let Ok(bytes_read) = file.seek(SeekFrom::Start(start as u64)).and_then(|_| file.read(&mut buffer)) {
                buffer.truncate(bytes_read);

                let mut hasher = Sha256::new();
                hasher.update(buffer);
                let partial_hash = hasher.finalize();

                result.lock().unwrap().push(partial_hash);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let hashes = result.lock().unwrap();
    let final_hash = hashes.iter().fold(Sha256::new(), |mut hasher, hash| {
        hasher.update(hash);
        hasher
    }).finalize();

    Ok(final_hash.to_vec())
}
