use crate::utils::{
    AESMode, add_pkcs7_padding, decrypt_cbc_mode, decrypt_user_profile, detect_aes_mode,
    encrypt_cbc_mode, encrypt_user_profile, encryption_oracle, from_b64_to_u8,
    generate_sixteen_random_bytes, profile_for,
};
use openssl::symm::{Cipher, encrypt};
use std::collections::HashSet;

pub fn run_all() {
    challenge_nine();
    challenge_ten();
    challenge_eleven();
    challenge_twelve();
    challenge_thirteen();
    challenge_sixteen();
}

pub fn challenge_nine() {
    let bytes = b"YELLOW SUBMARINE";
    let padded_bytes = add_pkcs7_padding(bytes, 20);
    let result = [
        89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,
    ];
    assert_eq!(result, padded_bytes.as_slice());
    println!("Challenge 9: OK (PKCS#7 padding)");
}

pub fn challenge_ten() {
    let mut data = std::fs::read_to_string("challenge-data/challenge-data10.txt").unwrap();
    data.retain(|c| !c.is_whitespace());
    let bytes = from_b64_to_u8(&data);
    let key = b"YELLOW SUBMARINE";
    let iv = [0u8; 16];
    let decrypted = decrypt_cbc_mode(bytes.as_slice(), key, &iv);
    println!(
        "Challenge 10: {}",
        String::from_utf8_lossy(&decrypted)
    );
}

pub fn challenge_eleven() {
    let plaintext = std::fs::read_to_string("challenge-data/challenge-data11.txt").unwrap();
    let ciphertext = encryption_oracle(plaintext.as_bytes());
    let mode = detect_aes_mode(ciphertext.as_slice());
    match mode {
        AESMode::ECB => println!("Challenge 11: Detected ECB Mode"),
        AESMode::CBC => println!("Challenge 11: Detected CBC Mode"),
    }
}

pub fn challenge_twelve() {
    let hidden_string = brute_force_ecb_mode();
    println!(
        "Challenge 12: {}",
        String::from_utf8(hidden_string).unwrap()
    );
}

pub fn challenge_thirteen() {
    let mut input = Vec::from(b"foooo@bar.admin");
    for _ in 0..11 {
        input.push(10);
    }
    b"com".iter().for_each(|&byte| input.push(byte));

    let email = String::from_utf8(input).unwrap();
    let profile_string = profile_for(&email);
    let key = generate_sixteen_random_bytes();
    let ciphertext = encrypt_user_profile(&profile_string, &key);
    let mut modified_ciphertext = Vec::new();
    modified_ciphertext.extend_from_slice(&ciphertext[0..16]);
    modified_ciphertext.extend_from_slice(&ciphertext[32..48]);
    modified_ciphertext.extend_from_slice(&ciphertext[16..32]);
    println!(
        "Challenge 13: {}",
        decrypt_user_profile(&modified_ciphertext, &key)
    );
}

pub fn challenge_fourteen() {
    let hidden_string = brute_force_ecb_mode_harder();
    println!(
        "Challenge 14: {}",
        String::from_utf8(hidden_string).unwrap()
    );
}

fn discover_ecb_block_size() -> usize {
    let byte = b'A';
    let mut block_size = 0;
    while block_size < 100 {
        let bytes = vec![byte; block_size];
        let ciphertext = challenge_twelve_helper(&bytes);
        if let AESMode::ECB = detect_aes_mode(&ciphertext) {
            block_size /= 2; // since we found a repeat we need to halve the block size
            break;
        }
        block_size += 1;
    }
    block_size
}

// Given AESECB( your_input | hidden_string ) with a consistent key, find the next byte of hidden string.
fn decrypt_ecb_one_byte(known_bytes: &[u8], block_size: usize) -> Option<u8> {
    let mut table = HashSet::new();
    let mut decrypted_byte = None;
    let num_bytes_to_input = block_size - (known_bytes.len() % block_size) - 1;
    let block_number = known_bytes.len() / block_size + 1;
    let mut input_bytes = vec![0u8; num_bytes_to_input];

    let mut encrypted = challenge_twelve_helper(&input_bytes);
    encrypted.truncate(block_size * block_number);
    encrypted.drain(0..(encrypted.len() - block_size));
    table.insert(encrypted);

    input_bytes.extend_from_slice(known_bytes);

    for byte in 0..=255 {
        input_bytes.push(byte);
        encrypted = challenge_twelve_helper(&input_bytes);
        encrypted.truncate(block_size * block_number);
        encrypted.drain(0..(encrypted.len() - block_size));
        match table.get(&encrypted) {
            Some(_) => {
                decrypted_byte = Some(byte);
                break;
            }
            None => table.insert(encrypted),
        };
        input_bytes.pop();
    }
    decrypted_byte
}

fn brute_force_ecb_mode() -> Vec<u8> {
    let mut hidden_string = Vec::new();
    let block_size = discover_ecb_block_size();
    loop {
        match decrypt_ecb_one_byte(&hidden_string, block_size) {
            Some(byte) => hidden_string.push(byte),
            None => break,
        }
    }
    hidden_string
}

fn detect_prefix_length_challenge_fourteen() -> usize {
    let control = [0u8; 1];
    let beacon = [1u8; 1];
    let mut control_encryption = challenge_fourteen_helper(&control);
    let mut beacon_encryption = challenge_fourteen_helper(&beacon);
    let mut block_number = 0;
    let index = block_number * 16;

    while block_number < control_encryption.len() {
        if control_encryption[index..index + 16] != beacon_encryption[index..index + 16] {
            break;
        }
        block_number += 1;
    }

    let mut padding_length = 0;
    while control_encryption[index..index + 16] != beacon_encryption[index..index + 16] {
        padding_length += 1;
        let control = vec![0u8; padding_length + 1];
        let mut beacon = vec![0u8; padding_length];
        beacon.push(1);
        control_encryption = challenge_fourteen_helper(&control);
        beacon_encryption = challenge_fourteen_helper(&beacon);
    }
    if block_number == 0 {
        16 - padding_length
    } else {
        block_number * 16 - padding_length
    }
}

fn decrypt_ecb_one_byte_harder(
    prefix_length: usize,
    known_bytes: &[u8],
    block_size: usize,
) -> Option<u8> {
    let mut table = HashSet::new();
    let mut decrypted_byte = None;
    let num_bytes_to_input =
        block_size + (block_size - prefix_length) - (known_bytes.len() % block_size) - 1;
    let block_number = (prefix_length + num_bytes_to_input + known_bytes.len()) / block_size + 1;
    let mut input_bytes = vec![0u8; num_bytes_to_input];

    let mut encrypted = challenge_fourteen_helper(&input_bytes);
    encrypted.truncate(block_size * block_number);
    encrypted.drain(0..(encrypted.len() - block_size));
    table.insert(encrypted);

    input_bytes.extend_from_slice(known_bytes);

    for byte in 0..=255 {
        input_bytes.push(byte);
        encrypted = challenge_fourteen_helper(&input_bytes);
        encrypted.truncate(block_size * block_number);
        encrypted.drain(0..(encrypted.len() - block_size));
        match table.get(&encrypted) {
            Some(_) => {
                decrypted_byte = Some(byte);
                break;
            }
            None => table.insert(encrypted),
        };
        input_bytes.pop();
    }
    decrypted_byte
}

fn brute_force_ecb_mode_harder() -> Vec<u8> {
    let mut hidden_string = Vec::new();
    let block_size = discover_ecb_block_size();
    let prefix_length = detect_prefix_length_challenge_fourteen();
    loop {
        match decrypt_ecb_one_byte_harder(prefix_length, &hidden_string, block_size) {
            Some(byte) => hidden_string.push(byte),
            None => break,
        }
    }
    hidden_string
}

fn challenge_twelve_helper(bytes: &[u8]) -> Vec<u8> {
    let key = b"bat wings sing t";
    let cipher = Cipher::aes_128_ecb();
    let encoded_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let string_to_append = from_b64_to_u8(encoded_string);
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(bytes);
    plaintext.extend_from_slice(string_to_append.as_slice());
    encrypt(cipher, key, None, plaintext.as_slice()).unwrap()
}

fn challenge_fourteen_helper(bytes: &[u8]) -> Vec<u8> {
    let decision_number = 5; // Hardcoding this only because it needs to be consistent between calls
    let key = b"bat wings sing t";
    let cipher = Cipher::aes_128_ecb();
    let encoded_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let string_to_append = from_b64_to_u8(encoded_string);
    let mut plaintext = Vec::new();
    let preappending_count = (decision_number % 6) + 5;
    let preappending_content = vec![0u8; preappending_count as usize];
    plaintext.extend_from_slice(&preappending_content);
    plaintext.extend_from_slice(bytes);
    plaintext.extend_from_slice(&string_to_append);
    encrypt(cipher, key, None, plaintext.as_slice()).unwrap()
}

fn challenge_16_string(input: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let sanitized_input = input.replace(';', "%3B").replace('=', "%3D");
    let mut constructed_string = String::from("comment1=cooking%20MCs;userdata=");
    constructed_string.push_str(&sanitized_input);
    constructed_string.push_str(";comment2=%20like%20a%20pound%20of%20bacon");
    encrypt_cbc_mode(constructed_string.as_bytes(), key, iv)
}

fn challenge_16_authenticate_admin(bytes: &[u8], key: &[u8], iv: &[u8]) -> bool {
    let plaintext = decrypt_cbc_mode(bytes, key, iv);
    let string = String::from_utf8_lossy(&plaintext);
    string.contains(";admin=true;")
}

pub fn challenge_sixteen() {
    let input = "YELLOW_SUBMARINE:admin<true";
    let key = generate_sixteen_random_bytes();
    let iv = generate_sixteen_random_bytes();
    let mut ciphertext = challenge_16_string(input, &key, &iv);
    ciphertext[32] ^= 0x01;
    ciphertext[38] ^= 0x01;
    let is_admin = challenge_16_authenticate_admin(&ciphertext, &key, &iv);
    if is_admin {
        println!("Challenge 16: Successfully forged admin creds.");
    } else {
        println!("Challenge 16: Failed to forge admin creds.");
    }
}
