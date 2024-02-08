use std::io::Write;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;


fn des_decode(data: &[u8], head: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::des_ecb();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, head, None)?;
    let mut result = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut result)?;
    let final_result = result[..count].to_vec();
    Ok(final_result)
}

fn decode_pass(data: &str) -> Result<String, openssl::error::ErrorStack> {
    if let Some(data) = base64::decode(data).ok() {
        let head = &data[..8];
        let d = &data[8..];
        let key = random_key(head);
        let bt = des_decode(d, &key)?;
        let rs = String::from_utf8(bt).unwrap();
        Ok(rs)
    } else {
        Err(openssl::error::ErrorStack::get())
    }
}

fn random_key(head: &[u8]) -> Vec<u8> {
    let ks: u64 = 3680984568597093857 / (rand::thread_rng().gen_range(0..127) as u64);
    let mut random = rand::thread_rng();
    let t = head[0];

    for _ in 0..t {
        random.gen::<u64>();
    }

    let n = random.gen::<u64>();
    let mut ld = [
        head[4] as u64,
        random.gen::<u64>(),
        head[7] as u64,
        head[3] as u64,
        random.gen::<u64>(),
        head[1] as u64,
        random.gen::<u64>(),
        head[2] as u64,
    ];

    let mut key_data = Vec::new();
    let mut dos = Vec::new();

    for &l in ld.iter() {
        dos.write_all(&l.to_le_bytes()).unwrap();
    }

    key_data.extend_from_slice(&md5(&dos));

    key_data
}

fn md5(data: &[u8]) -> Vec<u8> {
    let digest = md5::compute(data);
    digest.to_vec()
}

fn main() {
    match decode_pass("ENTER_YOUR_ENCRYPTED_PASSWORD") {
        Ok(result) => println!("{}", result),
        Err(err) => eprintln!("Error: {}", err),
    }

}

