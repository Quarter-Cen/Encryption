use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

pub fn sign_hash(private_key: &SigningKey, hash: &[u8]) -> Signature {
    private_key.try_sign(hash).expect("Failed to sign the file")
}

pub fn verify_signature(public_key: &VerifyingKey, hash: &[u8], signature: &Signature) -> bool {
    public_key.verify(hash, signature).is_ok()
}
