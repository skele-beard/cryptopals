use crate::utils::*;
use openssl::symm::{Cipher, decrypt};
use std::collections::HashSet;

#[allow(dead_code)]
pub struct Challenges {
    set: u8,
}

impl Challenges {
    pub fn new() -> Challenges {
        Challenges { set: 1 }
    }
    pub fn set_one(&self) {
        self.challenge_one();
        self.challenge_two();
        self.challenge_three();
        self.challenge_four();
        self.challenge_five();
        self.challenge_six();
        self.challenge_seven();
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
        let data = std::fs::read_to_string("challenge-data/challenge-data6.txt").unwrap();
        let trimmed_data: String = data.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = from_b64_to_u8(&trimmed_data);
        let answer = break_repeating_key_xor(&bytes);
        println!(
            "The answer to challenge six is: {}",
            String::from_utf8(answer).unwrap()
        );
    }
    fn challenge_seven(&self) {
        let mut data = std::fs::read_to_string("challenge-data/challenge-data7.txt").unwrap();
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
        let data = std::fs::read_to_string("challenge-data/challenge-data8.txt").unwrap();
        //compare blocks in the same ciphertext and determine if there are repeated blocks
        for line in data.lines() {
            let bytes = from_hex_to_u8(line);
            let mut table = HashSet::new();
            for i in 1..10 {
                let block = &bytes[i * 16..i * 16 + 16];
                match table.get(&block) {
                    Some(_) => {
                        println!("The answer to challenge eight is {}", line);
                        return;
                    }
                    None => {
                        table.insert(block);
                    }
                }
            }
        }
    }
}
