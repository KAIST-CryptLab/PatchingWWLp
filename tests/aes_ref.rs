use patching_wwlp::aes_ref::*;
use rand::{thread_rng, Rng};
use aes::Aes128;
use aes::cipher::{KeyInit, BlockEncrypt, generic_array::GenericArray};

fn main() {
    for trial in 0..10 {
        println!("==== Trial {} ====", trial + 1);
        let mut rng = thread_rng();
        let mut key = [0u8; BLOCKSIZE_IN_BYTE];
        for i in 0..BLOCKSIZE_IN_BYTE {
            key[i] = rng.gen_range(0..=u8::MAX);
        }

        let aes_ref = Aes128Ref::new(&key);
        let aes = Aes128::new(&GenericArray::from(key));

        let mut message = [0u8; BLOCKSIZE_IN_BYTE];
        for i in 0..BLOCKSIZE_IN_BYTE {
            message[i] = rng.gen_range(0..=u8::MAX);
        }

        let output_ref = aes_ref.encrypt_block(message);

        let mut block = GenericArray::from(message);
        aes.encrypt_block(&mut block);

        println!("Key      : {key:>2x?}");
        println!("Message  : {message:>2x?}");
        println!("OutputRef: {output_ref:>2x?}");
        println!("Output   : {block:>2x?}");

        for i in 0..BLOCKSIZE_IN_BYTE {
            if output_ref[i] != block[i] {
                println!("\nEncryption failure!");
                return;
            }
        }
        println!();
    }
}
