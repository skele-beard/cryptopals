use base64::{Engine as _, engine::general_purpose};
use openssl::symm::{Cipher, decrypt};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

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

mod set1 {
    #[allow(dead_code)]
    pub struct Challenge {
        set: u8,
    }

    impl Challenge {
        pub fn new() -> Challenge {
            Challenge { set: 1 }
        }
        pub fn set_one(&self) {
            self.challenge_one();
            self.challenge_two();
            self.challenge_three();
            self.challenge_four();
            self.challenge_five();
            //self.challenge_six();
            //self.challenge_seven();
            self.challenge_eight();
        }
        fn challenge_one(&self) {
            let string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            let answer = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
            assert_eq!(from_hex_to_b64(string), answer);
        }
        fn challenge_two(&self) {
            let string1 = from_hex_to_u8("1c0111001f010100061a024b53535009181c");
            let string2 = from_hex_to_u8("686974207468652062756c6c277320657965");
            let answer = "746865206b696420646f6e277420706c6179";
            let attempt = hex::encode(xor_buffers(string1.as_slice(), string2.as_slice()));
            assert_eq!(attempt, answer);
        }
        fn challenge_three(&self) {
            let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            let bytes = from_hex_to_u8(ciphertext);
            let plaintext = break_single_byte_xor_cipher(bytes.as_slice());
            println!(
                "The answer to challenge three is: {}",
                String::from_utf8(plaintext).unwrap()
            );
        }
        fn challenge_four(&self) {
            let data = std::fs::read_to_string(
                "/home/chandler/crypto/cryptopals/src/challenge-data/challenge-data4.txt",
            )
            .unwrap();
            let mut max_score = f32::INFINITY;
            let mut plaintext = Vec::new();
            for line in data.lines() {
                let bytes = from_hex_to_u8(line);
                let string = break_single_byte_xor_cipher(&bytes);
                let score = calculate_frequency_score(&string);
                if score < max_score {
                    max_score = score;
                    plaintext = string;
                }
            }
            println!(
                "The answer to challenge four is: {}",
                String::from_utf8(plaintext.clone()).unwrap()
            );
        }
        fn challenge_five(&self) {
            let mut stanza = b"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
                .to_vec();
            apply_repeating_key_xor_in_place(&mut stanza, "ICE".as_bytes());
            let answer = hex::encode(stanza);
            assert_eq!(
                answer,
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
            )
        }
        fn challenge_six(&self) {
            let data = std::fs::read_to_string(
                "/home/chandler/crypto/cryptopals/src/challenge-data/challenge-data6.txt",
            )
            .unwrap();
            let trimmed_data: String = data.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = from_b64_to_u8(&trimmed_data);
            let answer = break_repeating_key_xor(&bytes);
            println!(
                "The answer to challenge six is: {}",
                String::from_utf8(answer).unwrap()
            );
        }
        fn challenge_seven(&self) {
            let mut data = std::fs::read_to_string(
                "/home/chandler/crypto/cryptopals/src/challenge-data/challenge-data7.txt",
            )
            .unwrap();
            data.retain(|c| !c.is_whitespace());
            let bytes = from_b64_to_u8(&data);
            let cipher = Cipher::aes_128_ecb();
            let answer = decrypt(cipher, b"YELLOW SUBMARINE", None, &bytes).unwrap();
            println!(
                "The answer to challenge seven is: {}",
                String::from_utf8(answer).unwrap()
            );
        }
        fn challenge_eight(&self) {
            let data = std::fs::read_to_string(
                "/home/chandler/crypto/cryptopals/src/challenge-data/challenge-data8.txt",
            )
            .unwrap();
            //compare blocks in the same ciphertext and determine if there are repeated blocks
            for line in data.lines() {
                let bytes = from_hex_to_u8(line);
                let mut table = HashSet::new();
                for i in 1..10 {
                    let block = &bytes[i * 16..i * 16 + 16];
                    match table.get(&block) {
                        Some(_) => {
                            println!("The answer to challenge eight is {}", line);
                        }
                        None => {
                            table.insert(block);
                        }
                    }
                }
            }
        }
    }
}

// utility functions
fn from_hex_to_b64(hex_str: &str) -> String {
    let bytes = hex::decode(hex_str).unwrap();
    general_purpose::STANDARD.encode(bytes)
}

fn from_hex_to_u8(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap()
}

fn from_b64_to_u8(b64_str: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(b64_str).unwrap()
}

fn xor_buffers(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
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
fn calculate_frequency_score(bytes: &[u8]) -> f32 {
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
    println!("{:?}", scores);

    scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    println!("{:?}", scores);
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
        println!("{}", String::from_utf8_lossy(&key));
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
