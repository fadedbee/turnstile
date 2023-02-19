pub mod common;
pub mod base62;
pub mod decrypt;
pub mod encrypt;
pub mod io;
pub mod keygen;

#[cfg(test)]
mod tests {
    use sodiumoxide::crypto::box_::{self, PublicKey, Nonce};
    use crate::{encrypt, decrypt};

    #[test]
    fn test_encryption_and_decryption() {
        let (source_pkey, source_skey) = box_::gen_keypair();
        let (target_pkey, target_skey) = box_::gen_keypair();
        let initial_nonce = Nonce([123u8; 24]);

        let mut encrypted_file = Vec::<u8>::new();
        encrypt::_encrypt(&target_pkey, &source_pkey, &source_skey, &initial_nonce,
            &mut b"Mary had a little lamb".as_slice(), &mut encrypted_file).unwrap();

        assert_eq!(encrypted_file.len(), 104 + 2 + 22 + 16 + 2); 

        let mut decrypted_file = Vec::<u8>::new();
        decrypt::_decrypt("", &mut encrypted_file.as_slice(),
            // this closure fakes the lookup of the target_skey from the target_pkey
            Box::new(move |_keydir: &str, pkey: &PublicKey| {
                assert_eq!(pkey, &target_pkey);
                Ok(target_skey.clone())
            }), &mut decrypted_file).unwrap();

        assert_eq!(decrypted_file, b"Mary had a little lamb");
    }

    /// Test that box encryption and decrypton work.
    #[test]
    fn test_box() {
        let (ourpk, oursk) = box_::gen_keypair();
        let (theirpk, theirsk) = box_::gen_keypair();
        let our_precomputed_key = box_::precompute(&theirpk, &oursk);
        let nonce = box_::gen_nonce();
        let plaintext = b"plaintext";
        let ciphertext = box_::seal_precomputed(plaintext, &nonce, &our_precomputed_key);
        // this will be identical to our_precomputed_key
        let their_precomputed_key = box_::precompute(&ourpk, &theirsk);
        let their_plaintext = box_::open_precomputed(&ciphertext, &nonce,
                                                    &their_precomputed_key).unwrap();
        assert_eq!(plaintext, &their_plaintext[..]); 

        println!("ourpk {ourpk:?}, oursk {oursk:?}");
        println!("theirpk {theirpk:?}, theirsk {theirsk:?}");
        println!("our_precomputed_key {our_precomputed_key:?}");
        println!("their_precomputed_key {their_precomputed_key:?}");
        println!("plainetxt {plaintext:?}");
        println!("ciphertext {ciphertext:?}");
        println!("their_plaintext {their_plaintext:?}");
    }

    /// Check that a variety of messages all encrypt to a box which is 16 bytes larger.
    #[test]
    fn test_box_size() {
        let (_ourpk, oursk) = box_::gen_keypair();
        let (theirpk, _theirsk) = box_::gen_keypair();
        let our_precomputed_key = box_::precompute(&theirpk, &oursk);
        let nonce = box_::gen_nonce();

        for plaintext in [
            Vec::from(['a' as u8; 0]),
            Vec::from(['b' as u8; 1]),
            Vec::from(['c' as u8; 255]),
            Vec::from(['d' as u8; 256]),
            Vec::from(['e' as u8; 257]),
            Vec::from(['f' as u8; 65535]),
            Vec::from(['g' as u8; 65536]),
            Vec::from(['h' as u8; 65537]),
        ] {
            let ciphertext = box_::seal_precomputed(&plaintext, &nonce, &our_precomputed_key);
            println!("plaintext.len(): {}, ciphertext.len(): {}", plaintext.len(), ciphertext.len());
            assert_eq!(plaintext.len() + 16, ciphertext.len());
        }
    }

    /// Check that box decryption detects corruption, rather tha producing corrupted plaintext.
    #[test]
    fn test_box_integrity() {
        let (ourpk, oursk) = box_::gen_keypair();
        let (theirpk, theirsk) = box_::gen_keypair();
        let our_precomputed_key = box_::precompute(&theirpk, &oursk);
        let nonce = box_::gen_nonce();
        let plaintext = b"plaintext";
        let mut ciphertext = box_::seal_precomputed(plaintext, &nonce, &our_precomputed_key);
        ciphertext[21] = 42; // corruption

        // this will be identical to our_precomputed_key
        let their_precomputed_key = box_::precompute(&ourpk, &theirsk);
        let result = box_::open_precomputed(&ciphertext, &nonce,
                                                    &their_precomputed_key);
        assert_eq!(result, Err(()));                    
    }
}