use crate::utils::*;
use openssl::symm::{Cipher, decrypt};
use std::collections::HashSet;

pub fn run_all() {
    challenge_one();
    challenge_two();
    challenge_three();
    challenge_four();
    challenge_five();
    challenge_six();
    challenge_seven();
    challenge_eight();
}

pub fn challenge_one() {
    let string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let answer = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(from_hex_to_b64(string), answer);
    println!("Challenge 1: OK (hex to base64)");
}

pub fn challenge_two() {
    let string1 = from_hex_to_u8("1c0111001f010100061a024b53535009181c");
    let string2 = from_hex_to_u8("686974207468652062756c6c277320657965");
    let answer = "746865206b696420646f6e277420706c6179";
    let attempt = hex::encode(xor_buffers(string1.as_slice(), string2.as_slice()));
    assert_eq!(attempt, answer);
    println!("Challenge 2: OK (fixed XOR)");
}

pub fn challenge_three() {
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = from_hex_to_u8(ciphertext);
    let plaintext = break_single_byte_xor_cipher(bytes.as_slice());
    println!(
        "Challenge 3: {}",
        String::from_utf8(plaintext).unwrap()
    );
}

pub fn challenge_four() {
    let data = std::fs::read_to_string("challenge-data/challenge-data4.txt").unwrap();
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
        "Challenge 4: {}",
        String::from_utf8(plaintext.clone()).unwrap()
    );
}

pub fn challenge_five() {
    let mut stanza = b"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
        .to_vec();
    apply_repeating_key_xor_in_place(&mut stanza, "ICE".as_bytes());
    let answer = hex::encode(stanza);
    assert_eq!(
        answer,
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
    println!("Challenge 5: OK (repeating key XOR)");
}

pub fn challenge_six() {
    let data = std::fs::read_to_string("challenge-data/challenge-data6.txt").unwrap();
    let trimmed_data: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = from_b64_to_u8(&trimmed_data);
    let answer = break_repeating_key_xor(&bytes);
    println!(
        "Challenge 6: {}",
        String::from_utf8(answer).unwrap()
    );
}

pub fn challenge_seven() {
    let mut data = std::fs::read_to_string("challenge-data/challenge-data7.txt").unwrap();
    data.retain(|c| !c.is_whitespace());
    let bytes = from_b64_to_u8(&data);
    let cipher = Cipher::aes_128_ecb();
    let answer = decrypt(cipher, b"YELLOW SUBMARINE", None, &bytes).unwrap();
    println!(
        "Challenge 7: {}",
        String::from_utf8(answer).unwrap()
    );
}

pub fn challenge_eight() {
    let data = std::fs::read_to_string("challenge-data/challenge-data8.txt").unwrap();
    for line in data.lines() {
        let bytes = from_hex_to_u8(line);
        let mut table = HashSet::new();
        for block in bytes.chunks(16) {
            match table.get(&block) {
                Some(_) => {
                    println!("Challenge 8: {}", line);
                    return;
                }
                None => {
                    table.insert(block);
                }
            }
        }
    }
}
