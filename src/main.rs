use base64::{engine::general_purpose, Engine as _};
use cipher::BlockDecrypt;
use md5 as md5_lib;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use des::cipher::{KeyInit, generic_array::GenericArray};
use des::Des;
use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("请输入加密密码：");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let encrypted_pass = input.trim();

    match decode_pass(encrypted_pass) {
        Ok(decoded) => {
            println!("解密后的密码：{}", decoded);
        }
        Err(e) => {
            eprintln!("解密失败: {}", e);
        }
    }
    Ok(())
}

// 核心解密函数
fn decode_pass(encrypted: &str) -> Result<String, Box<dyn std::error::Error>> {
    let buf = general_purpose::STANDARD.decode(encrypted)?;
    
    if buf.len() <= 8 {
        return Err("数据长度不足".into());
    }

    let head = &buf[..8];
    let data = &buf[8..];
    let key = random_key(head)?;
    
    let decrypted = des_decode(data, &key)?;
    
    // 将解密后的字节转换为UTF-8字符串
    String::from_utf8(decrypted)
        .map_err(|e| format!("解密结果不是有效的UTF-8文本: {}", e).into())
}

// Java风格的Random实现
struct Random {
    seed: i64,
}

impl Random {
    fn from_seed(seed: i64) -> Self {
        Random { 
            seed: (seed ^ 0x5DEECE66D) & ((1i64 << 48) - 1)
        }
    }

    fn next(&mut self, bits: i32) -> i32 {
        self.seed = (self.seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB)) & ((1i64 << 48) - 1);
        (self.seed >> (48 - bits)) as i32
    }

    fn next_long(&mut self) -> i64 {
        let high = self.next(32) as i64 & 0xFFFFFFFF;
        let low = self.next(32) as i64 & 0xFFFFFFFF;
        (high << 32) | low
    }

    fn gen_range(&mut self, range: std::ops::Range<i32>) -> i32 {
        let n = (range.end - range.start) as u32;
        if n == 0 {
            range.start
        } else {
            range.start.wrapping_add((self.next(31).wrapping_abs() as u32 % n) as i32)
        }
    }
}

// 随机密钥生成函数
fn random_key(head: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let rand_num = Random::from_seed(head[5] as i64).gen_range(1..127);
    let ks = 3680984568597093857i64.wrapping_div(rand_num as i64);
    let mut random = Random::from_seed(ks);
    let t = head[0];

    for _ in 0..t {
        random.next_long();
    }

    let n = random.next_long();
    let mut r2 = Random::from_seed(n);

    // 按照 JavaScript 实现的字节顺序构建数据
    let mut data = Vec::with_capacity(64);
    // head[4], r2.nextLong(), head[7], head[3], r2.nextLong(), head[1], random.nextLong(), head[2]
    let mut add_long = |val: i64| {
        data.extend_from_slice(&val.to_be_bytes());
    };

    add_long(head[4] as i64);
    add_long(r2.next_long());
    add_long(head[7] as i64);
    add_long(head[3] as i64);
    add_long(r2.next_long());
    add_long(head[1] as i64);
    add_long(random.next_long());
    add_long(head[2] as i64);

    // 只取 MD5 的前 16 字节作为密钥
    let md5_result = md5_hash(&data);
    Ok(md5_result[..8].to_vec())
}

// MD5哈希函数
fn md5_hash(data: &[u8]) -> Vec<u8> {
    let digest = md5_lib::compute(data);
    digest.to_vec()
}

// DES解密函数
fn des_decode(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::from_slice(&key[..8]);
    let cipher = Des::new(key);
    
    let mut result = Vec::new();
    
    // ECB 模式解密
    for chunk in data.chunks_exact(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        result.extend_from_slice(&block);
    }

    // PKCS7 填充处理
    if !result.is_empty() {
        let padding_len = result[result.len() - 1] as usize;
        if padding_len > 0 && padding_len <= 8 && result.len() >= padding_len {
            // 验证所有填充字节是否相同
            if result[result.len() - padding_len..].iter().all(|&x| x == padding_len as u8) {
                result.truncate(result.len() - padding_len);
            }
        }
    }
    
    Ok(result)
}
