use crate::utils::{break_repeating_key_xor_known_key_len, from_b64_to_u8};
use crate::utils::{
    encrypt_cbc_mode, encrypt_ecb_mode, generate_sixteen_random_bytes, strip_padding, xor_buffers,
};
use aes::cipher::BlockDecrypt;
use aes::cipher::KeyInit;
use aes::{Aes128, cipher::generic_array::GenericArray};
use std::fs;

pub fn run_all() {
    challenge_seventeen();
    challenge_eighteen();
    challenge_twenty();
}

pub fn challenge_seventeen_create_cookie(key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cookies = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];
    let bytes: Vec<Vec<u8>> = cookies.iter().map(|c| from_b64_to_u8(c)).collect();
    let random_selection = (generate_sixteen_random_bytes()[0] % 10) as usize;
    let cookie = &bytes[random_selection];
    encrypt_cbc_mode(cookie, key, iv)
}

pub fn challenge_seventeen_consume_cookie(encrypted_cookie: &[u8], key: &[u8], iv: &[u8]) -> bool {
    let cookie = leaky_decrypt_cbc_mode(&encrypted_cookie, key, iv);
    strip_padding(&cookie).is_ok()
}

pub fn leaky_decrypt_cbc_mode(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::new();
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut prev_block = None;
    let mut temp_data = GenericArray::clone_from_slice(&[0; 16]);
    for block in bytes.chunks(16) {
        cipher.decrypt_block_b2b(&GenericArray::clone_from_slice(block), &mut temp_data);
        match prev_block {
            None => {
                plaintext.append(&mut xor_buffers(&temp_data, iv));
            }
            Some(prev_block) => {
                plaintext.append(&mut xor_buffers(&temp_data, prev_block));
            }
        }
        prev_block = Some(block);
    }
    plaintext
}

pub fn challenge_seventeen() {
    let key = b"bat wings sing t";
    let iv = b"his liminal hymn";
    // Collect the last two blocks
    // make changes to the ciphertext byte in block n - 1
    // check for valid padding
    // save 0 into that block
    // repeat
    let ciphertext = challenge_seventeen_create_cookie(key, iv);
    let length = ciphertext.len();
    let mut blocks = Vec::new();
    let mut block_number = 1;

    while blocks.len() * 16 < length {
        let block_n_idx = length - 16 * block_number;
        let block_n = ciphertext[block_n_idx..block_n_idx + 16].to_vec();
        let original_block_n_minus_one: Vec<u8> = if block_n_idx == 0 {
            iv.to_vec()
        } else {
            ciphertext[block_n_idx - 16..block_n_idx].to_vec()
        };

        let mut zeroing_iv = vec![0u8; 16];
        let mut block_plaintext = vec![0u8; 16];

        for i in (0..16).rev() {
            let padding_byte = (16 - i) as u8;
            let mut trial_block = vec![0u8; 16];
            for k in (i + 1)..16 {
                trial_block[k] = zeroing_iv[k] ^ padding_byte;
            }
            let mut found = false;
            for j in 0..=255u8 {
                trial_block[i] = j;
                if challenge_seventeen_consume_cookie(&block_n, key, &trial_block) {
                    zeroing_iv[i] = j ^ padding_byte;
                    block_plaintext[i] = zeroing_iv[i] ^ original_block_n_minus_one[i];
                    found = true;
                    break;
                }
            }
            if !found {
                println!("No valid byte found at position {}", i);
            }
        }

        blocks.push(block_plaintext);
        block_number += 1;
    }

    blocks.reverse();
    let mut plaintext: Vec<u8> = blocks.into_iter().flatten().collect();

    if let Some(&pad) = plaintext.last() {
        let pad = pad as usize;
        if pad <= 16 {
            plaintext.truncate(plaintext.len() - pad);
        }
    }
    println!(
        "The plaintext is: {}",
        String::from_utf8(plaintext).unwrap()
    );
}

pub fn encrypt_ctr_mode(bytes: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    let mut counter = [0u8; 16];
    let mut ciphertext = vec![];
    counter[0..8].copy_from_slice(&nonce.to_le_bytes());
    for (num_blocks, block) in bytes.chunks(16).enumerate() {
        if block.len() != 16 {
            let counter = &counter[0..block.len()];
            let keystream = &encrypt_ecb_mode(counter, key)[0..block.len()];
            ciphertext.extend_from_slice(&xor_buffers(keystream, block));
        } else {
            counter[8..].copy_from_slice(&num_blocks.to_le_bytes());
            let keystream = &encrypt_ecb_mode(&counter, key)[0..16];
            ciphertext.extend_from_slice(&xor_buffers(keystream, block));
        }
    }
    ciphertext
}

pub fn decrypt_ctr_mode(bytes: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    let mut counter = [0u8; 16];
    let mut ciphertext = vec![];
    counter[0..8].copy_from_slice(&nonce.to_le_bytes());
    for (num_blocks, block) in bytes.chunks(16).enumerate() {
        if block.len() != 16 {
            let counter = &counter[0..block.len()];
            let keystream = &encrypt_ecb_mode(counter, key)[0..block.len()];
            ciphertext.extend_from_slice(&xor_buffers(keystream, block));
        } else {
            counter[8..].copy_from_slice(&num_blocks.to_le_bytes());
            let keystream = &encrypt_ecb_mode(&counter, key)[0..16];
            ciphertext.extend_from_slice(&xor_buffers(keystream, block));
        }
    }
    ciphertext
}

pub fn challenge_eighteen() {
    let ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let bytes = from_b64_to_u8(ciphertext);
    let key = b"YELLOW SUBMARINE";
    let nonce = 0;
    println!(
        "Plaintext: {}",
        String::from_utf8_lossy(&decrypt_ctr_mode(&bytes, key, nonce))
    );
}

pub fn challenge_nineteen() {
    println!(
        "Challenge 19 does not seem more intuitive than challenge 20 and seems slower as well. I will skip it."
    );
}

pub fn challenge_twenty() {
    // get data
    let data = fs::read_to_string("challenge-data/challenge-data20.txt").unwrap();
    let plaintexts: Vec<&str> = data.split('\n').filter(|s| !s.is_empty()).collect();
    let bytes: Vec<Vec<u8>> = plaintexts.into_iter().map(from_b64_to_u8).collect();
    let key = &generate_sixteen_random_bytes();
    let nonce = 0;
    let ciphertexts: Vec<Vec<u8>> = bytes
        .iter()
        .map(|b| encrypt_ctr_mode(b, key, nonce))
        .collect();
    let key_len = ciphertexts.iter().map(|v| v.len()).min().unwrap_or(1);
    let concatenated_ciphertexts: Vec<u8> = ciphertexts
        .iter()
        .flat_map(|b| b[0..key_len].to_vec())
        .collect();
    println!(
        "Attempted plaintext: {}",
        String::from_utf8_lossy(&break_repeating_key_xor_known_key_len(
            &concatenated_ciphertexts,
            key_len
        ))
    )
}
