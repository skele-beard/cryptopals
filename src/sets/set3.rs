use crate::utils::{break_repeating_key_xor_known_key_len, from_b64_to_u8};
use crate::utils::{
    encrypt_cbc_mode, encrypt_ecb_mode, generate_sixteen_random_bytes, strip_padding, xor_buffers,
};
use aes::cipher::BlockDecrypt;
use aes::cipher::KeyInit;
use aes::{Aes128, cipher::generic_array::GenericArray};
use rand;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};
use std::{fs, time};

pub fn run_all() {
    challenge_seventeen();
    challenge_eighteen();
    challenge_twenty();
    challenge_twentyone();
    challenge_twentytwo();
    challenge_twentythree();
    challenge_twentyfour();
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

/*
  The general algorithm is characterized by the following quantities:

    w : word size (in number of bits)
    n : degree of recurrence
    m : middle word, an offset used in the recurrence relation defining the series x {\displaystyle x}, 1 ≤ m < n {\displaystyle 1\leq m<n}
    r : separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w − 1 {\displaystyle 0\leq r\leq w-1}
    a : coefficients of the rational normal form twist matrix
    b , c : TGFSR(R) tempering bitmasks
    s , t : TGFSR(R) tempering bit shifts
    u , d , l : additional Mersenne Twister tempering bit shifts/masks
*/
const MT_N: usize = 624;
const MT_W: u32 = 32;
const MT_M: usize = 397;
const MT_F: u32 = 1812433253;
const MT_R: u32 = 31;
const MT_UMASK: u32 = 0xffffffffu32.wrapping_shl(MT_R);
const MT_LMASK: u32 = !MT_UMASK; // LMASK is just the inverse of UMASK
const MT_A: u32 = 0x9908b0df;
const MT_U: u32 = 11;
const MT_S: u32 = 7;
const MT_T: u32 = 15;
const MT_L: u32 = 18;
const MT_B: u32 = 0x9d2c5680;
const MT_C: u32 = 0xefc60000;

pub struct MersenneTwister {
    state: [u32; MT_N],
    index: usize,
}

impl MersenneTwister {
    #[allow(clippy::needless_range_loop)]
    pub fn new(mut seed: u32) -> MersenneTwister {
        let mut state = [0u32; MT_N];
        state[0] = seed;
        for i in 1..MT_N {
            seed = MT_F
                .wrapping_mul(seed ^ (seed >> (MT_W - 2)))
                .wrapping_add(i as u32);
            state[i] = seed;
        }
        MersenneTwister { state, index: 0 }
    }

    pub fn rand_u32(&mut self) -> u32 {
        let k = self.index;
        let j = (k + 1) % MT_N; // next index, wrapping
        let m = (k + MT_M) % MT_N; // index m steps ahead, wrapping

        let x = (self.state[k] & MT_UMASK) | (self.state[j] & MT_LMASK);
        let mut xa = x >> 1;
        if x & 1 == 1 {
            xa ^= MT_A;
        }

        self.state[k] = self.state[m] ^ xa;
        let x = self.state[k];

        self.index = j; // advance index

        // tempering
        let mut y = x ^ (x >> MT_U);
        y ^= (y << MT_S) & MT_B;
        y ^= (y << MT_T) & MT_C;
        y ^ (y >> MT_L)
    }
}

pub fn challenge_twentyone() {
    let mut mt = MersenneTwister::new(0);
    for _ in 0..100000 {
        println!("{}", mt.rand_u32())
    }
}

pub fn challenge_twentytwo() {
    let mut random_wait_time: u64 = rand::random_range(40..100);
    thread::sleep(Duration::from_secs(random_wait_time));
    let unix_timestamp = time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rng = MersenneTwister::new(unix_timestamp as u32);
    random_wait_time = rand::random_range(40..100);
    let random_output = rng.rand_u32();
    println!("The output of the RNG is: {}", random_output);
    println!("The seed was {}", unix_timestamp as u32);

    let mut output = 0;
    let mut attacker_unix_timestamp = time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    while output != random_output {
        let mut rng = MersenneTwister::new(attacker_unix_timestamp as u32);
        output = rng.rand_u32();
        attacker_unix_timestamp -= 1;
    }
    assert_eq!(output, random_output);
    println!(
        "The seed was discovered to be: {}",
        attacker_unix_timestamp as u32 + 1
    );
}

pub fn undo_left_shift(input: u32, shift: u32, mask: u32) -> u32 {
    if shift >= 16 {
        println!("Chose easy path");
        input ^ ((input << shift) & mask)
    } else {
        let mut output = input;
        for _ in 0..32u32.div_ceil(shift) {
            output = input ^ ((output << shift) & mask)
        }
        output
    }
}

pub fn undo_right_shift(input: u32, shift: u32, mask: u32) -> u32 {
    if shift >= 16 {
        input ^ (input >> shift)
    } else {
        let mut output = input;
        for _ in 0..32u32.div_ceil(shift) {
            output = input ^ ((output >> shift) & mask)
        }
        output
    }
}

pub fn untemper(input: u32) -> u32 {
    let mut output = undo_right_shift(input, MT_L, 0xFFFFFFFF);
    output = undo_left_shift(output, MT_T, MT_C);
    output = undo_left_shift(output, MT_S, MT_B);
    undo_right_shift(output, MT_U, 0xFFFFFFFF)
}

pub fn challenge_twentythree() {
    #[allow(clippy::needless_range_loop)]
    let mut twister = MersenneTwister::new(90);
    let mut stolen_state = [0u32; MT_N];
    for i in 0..624 {
        stolen_state[i] = untemper(twister.rand_u32());
    }
    let mut cloned_twister = MersenneTwister {
        index: 0,
        state: stolen_state,
    };
    for _ in 0..10000 {
        assert_eq!(twister.rand_u32(), cloned_twister.rand_u32());
    }
}

pub fn encrypt_mt_stream_cipher(plaintext: &[u8], seed: u16) -> Vec<u8> {
    let mut prng = MersenneTwister::new(seed as u32);
    let mut ciphertext = Vec::new();
    for &byte in plaintext {
        ciphertext.push(byte ^ prng.rand_u32() as u8);
    }
    ciphertext
}

pub fn decrypt_mt_stream_cipher(ciphertext: &[u8], seed: u16) -> Vec<u8> {
    let mut prng = MersenneTwister::new(seed as u32);
    let mut plaintext = Vec::new();
    for &byte in ciphertext {
        plaintext.push(byte ^ prng.rand_u32() as u8);
    }
    plaintext
}

pub fn recover_mt_stream_cipher_key(ciphertext: &[u8], known_plaintext: &[u8]) -> u16 {
    for seed in 0..u16::MAX {
        if decrypt_mt_stream_cipher(ciphertext, seed).ends_with(known_plaintext) {
            return seed;
        }
    }
    panic!("No seed could be recovered.");
}

pub fn challenge_twentyfour() {
    let known_plaintext = b"AAAAAAAAAAAAAA";
    let rand_num_bytes = (generate_sixteen_random_bytes()[0] % 16) as usize;

    let mut plaintext: Vec<u8> = Vec::new();
    plaintext.extend_from_slice(&generate_sixteen_random_bytes()[0..rand_num_bytes]);
    plaintext.extend_from_slice(known_plaintext);

    let seed = generate_sixteen_random_bytes()[0] as u16;
    let ciphertext = encrypt_mt_stream_cipher(&plaintext, seed);
    let recovered_seed = recover_mt_stream_cipher_key(&ciphertext, known_plaintext);
    assert_eq!(seed, recovered_seed);
}
