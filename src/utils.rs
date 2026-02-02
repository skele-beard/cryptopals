use base64::{Engine as _, engine::general_purpose};
use openssl::symm::{Cipher, Crypter, Mode, decrypt, encrypt};
use std::collections::HashMap;

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

pub fn add_pkcs7_padding(bytes: &[u8], block_length: u8) -> Vec<u8> {
    //let padding_value = block_length as usize % bytes.len(); trying something different
    let padding_value = block_length - (bytes.len() % block_length as usize) as u8;
    let mut padded_bytes = bytes.to_vec();
    for i in 0..padding_value {
        padded_bytes.push(padding_value);
    }
    println!("length: {}", padded_bytes.len());
    padded_bytes
}

pub fn encrypt_cbc_mode(bytes: &[u8], key: &[u8], iv: &[u8], block_length: u8) -> Vec<u8> {
    let bytes = add_pkcs7_padding(bytes, block_length);
    let mut encrypted_data = Vec::new();
    let cipher = Cipher::aes_128_ecb();
    let mut prev_block = None;
    let mut temp_data = Vec::new();
    for block in bytes.chunks(16) {
        println!("block: {:?}", block);
        match prev_block {
            None => {
                temp_data = xor_buffers(block, iv);
            }
            Some(prev_block) => {
                temp_data = xor_buffers(block, prev_block);
            }
        }
        encrypted_data.append(&mut encrypt(cipher, key, None, &temp_data).unwrap());
        prev_block = Some(block);
    }
    encrypted_data
}

/*pub fn decrypt_cbc_mode(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::new();
    let cipher = Cipher::aes_128_ecb();
    let prev_block = None;
    let mut temp_data = Vec::new();
    for block in bytes.chunks(16) {
        temp_data = decrypt(cipher, key, None, block).unwrap();
        match prev_block {
            None => {
                plaintext.append(&mut xor_buffers(&temp_data, iv));
            }
            Some(prev_block) => {
                plaintext.append(&mut xor_buffers(&temp_data, prev_block));
            }
        }
    }
    plaintext
}*/
pub fn decrypt_cbc_mode(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::new();
    let mut cipher = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    cipher.pad(false);
    let mut prev_block = None;
    let mut temp_data = vec![0; 32];
    for block in bytes.chunks(16) {
        cipher.update(block, &mut temp_data).unwrap();
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
