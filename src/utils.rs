use aes::cipher::KeyInit;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes::{Aes128, cipher::generic_array::GenericArray};
use base64::{Engine as _, engine::general_purpose};
use openssl::rand;
use openssl::symm::{Cipher, decrypt, encrypt};
use std::collections::HashMap;
use std::collections::HashSet;

const CHAR_OFFSET: u8 = 97;
const NONASCII_PENALTY: f32 = 0.5;
const ASCII_SPACE: u8 = 32;
const ASCII_APHOSTROPHE: u8 = 39;
const ASCII_NEWLINE: u8 = 10;
const LETTER_FREQUENCIES: [f32; 26] = [
    0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.02, 0.061, 0.07, 0.0015, 0.0077, 0.04, 0.024,
    0.067, 0.075, 0.019, 0.00095, 0.06, 0.063, 0.091, 0.028, 0.0098, 0.024, 0.015, 0.02, 0.00074,
];
const ATTEMPTED_KEY_LENGTHS: usize = 40;
const BLOCK_LENGTH: usize = 16;

pub enum AESMode {
    ECB,
    CBC,
}

// utility functions
pub fn from_hex_to_b64(hex_str: &str) -> String {
    let bytes = hex::decode(hex_str).unwrap();
    general_purpose::STANDARD.encode(bytes)
}

pub fn from_hex_to_u8(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap()
}

pub fn from_b64_to_u8(b64_str: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(b64_str).unwrap()
}

pub fn xor_buffers(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    if buf1.len() != buf2.len() {
        panic!("Attempting to xor two buffers of differing length");
    }
    let mut new_buf = Vec::new();
    let mut i = 0;
    while i != buf1.len() {
        let byte1 = buf1.get(i).unwrap();
        let byte2 = buf2.get(i).unwrap();
        new_buf.push(byte1 ^ byte2);
        i += 1;
    }
    new_buf
}

//A smaller score is better
pub fn calculate_frequency_score(bytes: &[u8]) -> f32 {
    let mut occurences = HashMap::new();
    let mut score = 0.0;

    for &byte in bytes {
        if byte.is_ascii_alphabetic() {
            let normalized_byte = byte.to_ascii_lowercase();
            match occurences.get(&normalized_byte) {
                Some(times_seen) => occurences.insert(normalized_byte, times_seen + 1.0),
                _ => occurences.insert(normalized_byte, 1.0),
            };
        } else if byte == ASCII_SPACE || byte == ASCII_APHOSTROPHE || byte == ASCII_NEWLINE {
            continue;
        } else {
            score += NONASCII_PENALTY;
        }
    }

    for (letter, times_seen) in &occurences {
        let index: usize = (letter - CHAR_OFFSET) as usize; //this is necessary to map the letter a
        // to the byte 97, b to 98, etc
        let frequency_score =
            (LETTER_FREQUENCIES[index] - (times_seen / (occurences.len() as f32))).abs();
        score += frequency_score
    }

    score
}

pub fn break_single_byte_xor_cipher(bytes: &[u8]) -> Vec<u8> {
    let mut max_score = f32::INFINITY;
    let mut plaintext = Vec::new();
    for i in 0..=255 {
        let mut buffer = Vec::new();
        for byte in bytes {
            buffer.push(byte ^ i);
        }
        let score = calculate_frequency_score(&buffer);
        if score < max_score {
            max_score = score;
            plaintext = buffer;
        }
    }
    plaintext
}

pub fn find_key_single_byte_xor_cipher(bytes: &[u8]) -> u8 {
    let mut max_score = f32::INFINITY;
    let mut key = 0;
    for i in 0..=255 {
        let mut buffer = Vec::new();
        for byte in bytes {
            buffer.push(byte ^ i);
        }
        let score = calculate_frequency_score(&buffer);
        if score < max_score {
            max_score = score;
            key = i;
        }
    }
    key
}

pub fn apply_repeating_key_xor_in_place(bytes: &mut [u8], key: &[u8]) {
    let key_len = key.len();
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte ^= key[idx % key_len];
    }
}

pub fn apply_repeating_key_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key_len = key.len();
    let mut new_bytes = Vec::new();
    for (idx, &byte) in bytes.iter().enumerate() {
        new_bytes.push(byte ^ key[idx % key_len]);
    }
    new_bytes
}

//this should really be fixed. It's still sort of brute forcing all the plaintexts and it should
//be smart enough to only try a few based on the hamming distance.
pub fn break_repeating_key_xor(bytes: &[u8]) -> Vec<u8> {
    let mut scores = Vec::new();
    for possible_key_len in 1..=40 {
        let first_key_len_bytes = &bytes[0..possible_key_len];
        let second_key_len_bytes = &bytes[possible_key_len..2 * possible_key_len];
        let score = calculate_hamming_distance(first_key_len_bytes, second_key_len_bytes) as f32
            / (possible_key_len as f32);
        scores.push((possible_key_len, score));
    }

    scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    let contenders = scores.iter().take(ATTEMPTED_KEY_LENGTHS).map(|(k, _)| *k);

    let mut max_score = f32::INFINITY;
    let mut plaintext = Vec::new();
    for possible_key_len in contenders {
        let mut key = Vec::new();
        for i in 0..possible_key_len {
            let mut transposed_blocks = Vec::new();
            for (idx, &byte) in bytes.iter().enumerate() {
                if idx % possible_key_len == i {
                    transposed_blocks.push(byte);
                }
            }
            let key_byte = find_key_single_byte_xor_cipher(&transposed_blocks);
            key.push(key_byte);
        }
        let possible_plaintext = apply_repeating_key_xor(bytes, &key);
        let score = calculate_frequency_score(&possible_plaintext);
        if score < max_score {
            max_score = score;
            plaintext = possible_plaintext;
        }
    }
    plaintext
}

pub fn calculate_hamming_distance(buf1: &[u8], buf2: &[u8]) -> u32 {
    let xor_string: Vec<u8> = buf1
        .iter()
        .zip(buf2.iter())
        .map(|(&buf1_byte, &buf2_byte)| buf1_byte ^ buf2_byte)
        .collect();
    let hamming_distance = xor_string.iter().map(|&byte| byte.count_ones()).sum();
    hamming_distance
}

pub fn add_pkcs7_padding(bytes: &[u8], block_length: usize) -> Vec<u8> {
    let padding_value = (block_length - (bytes.len() % block_length)) as u8;
    let mut padded_bytes = bytes.to_vec();
    for i in 0..padding_value {
        padded_bytes.push(padding_value);
    }
    padded_bytes
}

pub fn remove_pkcs7_padding(bytes: &[u8], block_length: usize) -> Vec<u8> {
    let length = bytes.len();
    let start_of_last_block = length - block_length;
    let last_byte = length - 1;
    let last_block = &bytes[start_of_last_block..=last_byte];
    let padding_value = *last_block.last().unwrap();
    let mut unpadded_bytes = Vec::from(&bytes[0..start_of_last_block]);
    for &byte in last_block {
        if byte != padding_value {
            unpadded_bytes.push(byte);
        }
    }
    unpadded_bytes
}

pub fn encrypt_cbc_mode(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let bytes = add_pkcs7_padding(bytes, BLOCK_LENGTH);
    let mut encrypted_data = Vec::new();
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut prev_block = None;
    let mut temp_data = GenericArray::from([0u8; 16]);
    for block in bytes.chunks(16) {
        match prev_block {
            None => {
                temp_data = *GenericArray::from_slice(xor_buffers(block, iv).as_slice());
            }
            Some(prev_block) => {
                temp_data = *GenericArray::from_slice(xor_buffers(block, prev_block).as_slice());
            }
        }
        cipher.encrypt_block(&mut temp_data);
        prev_block = Some(temp_data.as_slice());
        encrypted_data.extend_from_slice(temp_data.as_slice());
    }
    encrypted_data
}

pub fn decrypt_cbc_mode(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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
    plaintext = remove_pkcs7_padding(plaintext.as_slice(), BLOCK_LENGTH);
    plaintext
}

pub fn generate_sixteen_random_bytes() -> [u8; 16] {
    let mut buf = [0; 16];
    rand::rand_bytes(&mut buf).unwrap();
    buf
}

pub fn encrypt_ecb_mode(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::new();

    //encrypt via ecb
    let cipher = Cipher::aes_128_ecb();
    let mut encrypted_data = encrypt(cipher, key, None, bytes).unwrap();
    ciphertext.append(&mut encrypted_data);
    ciphertext
}

pub fn decrypt_ecb_mode(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::new();

    //encrypt via ecb
    let cipher = Cipher::aes_128_ecb();
    let mut plaintext = decrypt(cipher, &key, None, bytes).unwrap();
    ciphertext.append(&mut plaintext);
    ciphertext
}

pub fn encryption_oracle(bytes: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    let mut plaintext = Vec::new();
    let key = generate_sixteen_random_bytes();
    let decision_number = key[0];

    //insert padding
    let appending_count = (decision_number % 6) + 5; // this guarantees between 5 and 10
    let appending_content = vec![0u8; appending_count as usize];
    plaintext.extend_from_slice(&appending_content);
    plaintext.extend_from_slice(bytes);
    plaintext.extend_from_slice(&appending_content);

    //if first byte of key is even then do ECB, if it's odd do CBC
    if decision_number % 2 == 0 {
        //encrypt via ecb
        println!("chose ECB Mode!");
        let cipher = Cipher::aes_128_ecb();
        let mut encrypted_data = encrypt(cipher, &key, None, bytes).unwrap();
        ciphertext.append(&mut encrypted_data);
    } else {
        println!("chose CBC Mode!");
        let iv = generate_sixteen_random_bytes();
        ciphertext = encrypt_cbc_mode(bytes, &key, &iv)
    }

    ciphertext
}

pub fn detect_aes_mode(bytes: &[u8]) -> AESMode {
    let mut table = HashSet::new();
    for block in bytes.chunks(16) {
        match table.get(&block) {
            Some(_) => {
                return AESMode::ECB;
            }
            None => {
                table.insert(block);
            }
        }
    }
    AESMode::CBC
}

// Write a k=v parsing routine, as if for a structured cookie. The routine should take:
//foo=bar&baz=qux&zap=zazzle
pub fn key_equals_value_parsing_routine(string: &str) -> HashMap<&str, &str> {
    let mut map = HashMap::new();
    let pairs = string.split('&');
    for pair in pairs {
        let equals_index = pair.find('=').unwrap();
        map.insert(&pair[0..equals_index], &pair[equals_index + 1..pair.len()]);
    }
    map
}

pub fn profile_for(email: &str) -> String {
    if email.find('=').is_some() {
        panic!("You cannot use the = character in your email address");
    }
    if email.find('&').is_some() {
        panic!("You cannot use the & character in your email address");
    }
    let mut profile_encoding = String::from("email=");
    profile_encoding.push_str(email);
    profile_encoding.push_str("&uid=10&role=user");
    //println!("{}", profile_encoding)
    profile_encoding
}

pub fn encrypt_user_profile(profile_string: &str, key: &[u8]) -> Vec<u8> {
    encrypt_ecb_mode(profile_string.as_bytes(), key)
}

pub fn decrypt_user_profile(ciphertext: &[u8], key: &[u8]) -> String {
    let bytes = decrypt_ecb_mode(ciphertext, key);
    String::from_utf8(bytes).unwrap()
}

pub fn strip_padding(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.is_empty() {
        return Err(String::from("Bytes are empty."));
    }
    if bytes.len() < 16 {
        return Err(String::from("Bytes do not create a full block"));
    }
    let padding_byte = bytes[bytes.len() - 1];
    if padding_byte == 0 || padding_byte > 16 {
        return Err(String::from("Invalid Padding"));
    }
    for i in 0..padding_byte {
        if bytes[bytes.len() - 1 - i as usize] != padding_byte {
            return Err(String::from("Invalid padding"));
        }
    }
    Ok(&bytes[0..bytes.len() - padding_byte as usize])
}
