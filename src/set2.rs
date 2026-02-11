use crate::utils::{
    AESMode, add_pkcs7_padding, brute_force_ecb_mode, decrypt_cbc_mode, detect_aes_mode,
    encryption_oracle, from_b64_to_u8,
};

#[allow(dead_code)]
pub struct Challenges {
    set: u8,
}

impl Challenges {
    pub fn new() -> Challenges {
        Challenges { set: 2 }
    }
    pub fn set_two(&self) {
        //self.challenge_nine();
        //self.challenge_ten();
        //self.challenge_eleven();
        self.challenge_twelve();
    }
    fn challenge_nine(&self) {
        let bytes = b"YELLOW SUBMARINE";
        let padded_bytes = add_pkcs7_padding(bytes, 20);
        let result = [
            89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,
        ];
        assert_eq!(result, padded_bytes.as_slice());
    }
    fn challenge_ten(&self) {
        let mut data = std::fs::read_to_string("challenge-data/challenge-data10.txt").unwrap();
        data.retain(|c| !c.is_whitespace());
        let bytes = from_b64_to_u8(&data);
        let key = b"YELLOW SUBMARINE";
        let iv = [0u8; 16];
        let decrypted = decrypt_cbc_mode(bytes.as_slice(), key, &iv);
        println!(
            "The answer to challenge ten is: {}",
            String::from_utf8_lossy(&decrypted)
        )
    }

    pub fn challenge_eleven(&self) {
        let plaintext = std::fs::read_to_string("challenge-data/challenge-data11.txt").unwrap();
        let ciphertext = encryption_oracle(plaintext.as_bytes());
        //println!("The ciphertext is: {:?}", ciphertext);
        let mode = detect_aes_mode(ciphertext.as_slice());
        match mode {
            AESMode::ECB => println!("Detected ECB Mode"),
            AESMode::CBC => println!("Detected CBC Mode"),
        }
    }

    pub fn challenge_twelve(&self) {
        let hidden_string = brute_force_ecb_mode();
        println!(
            "The string is: {}",
            String::from_utf8(hidden_string).unwrap()
        )
    }
}
