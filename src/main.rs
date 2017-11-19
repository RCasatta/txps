extern crate rocksdb;
extern crate rand;
extern crate secp256k1;
extern crate crypto;

use crypto::sha2::Sha256;
use crypto::digest::Digest;
use std::env;
use rocksdb::DB;
use rand::Rng;
use std::time::{Instant , Duration};
use secp256k1::{Secp256k1,Message};

const  N: usize = 1_000_000;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    key: u64,
}

impl  Key {
    pub fn new() -> Key {
        Key::from(rand::thread_rng().gen::<u64>())
    }
    pub fn from(key : u64) -> Key {
        Key {
            key: key,
        }
    }
    pub fn to_bytes(&self) -> [u8;8] {
        transform_u64_to_array_of_u8(self.key)
    }
}

fn main() {
    let default_dir = String::from("/tmp/storage");
    let mut dir = match env::args().nth(1) {
        Some(o) => o.parse::<String>().unwrap_or(default_dir),
        None => default_dir,
    };

    let n = match env::args().nth(2) {
        Some(o) => o.parse::<usize>().unwrap_or(N) ,
        None => N,
    };

    println!("DB: {} Working with {} elements", dir, n);

    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (sk,pk)=secp.generate_keypair(&mut rng).unwrap();

    let start = Instant::now();
    let mut bytes_vec = Vec::new();
    for i in 0..n {
        let mut bytes = [0u8;32];
        for j in 0..8 {
            bytes[j]=(i >> (j*8)) as u8;
        }
        bytes_vec.push(bytes);
    }
    elapsed("init messages", start.elapsed(), n);

    let start = Instant::now();
    let mut sign_vec = Vec::new();
    let sv_n = n / 20;
    for i in 0..sv_n {
        let message=Message::from_slice(&bytes_vec[i]).unwrap() ;
        let signature = secp.sign(&message, &sk).unwrap();
        sign_vec.push(signature);
    }
    elapsed("ecdsa sign", start.elapsed(), sv_n);

    let start = Instant::now();
    for i in 0..sv_n {
        let message=Message::from_slice(&bytes_vec[i]).unwrap() ;
        let signature = sign_vec[i];
        let r = secp.verify(&message, &signature, &pk);
        assert!(r.is_ok());
    }
    elapsed("ecdsa verify", start.elapsed(), sv_n);

    let start = Instant::now();
    let mut sign_schnorr_vec = Vec::new();
    for i in 0..sv_n {
        let message=Message::from_slice(&bytes_vec[i]).unwrap() ;
        let signature = secp.sign_schnorr(&message, &sk).unwrap();
        sign_schnorr_vec.push(signature);
    }
    elapsed("schnorr sign", start.elapsed(), sv_n);

    let start = Instant::now();
    for i in 0..sv_n {
        let message=Message::from_slice(&bytes_vec[i]).unwrap() ;
        let signature = sign_schnorr_vec[i];
        let r = secp.verify_schnorr(&message, &signature, &pk);
        assert!(r.is_ok());
    }
    elapsed("schnorr verify", start.elapsed(), sv_n);

    let start = Instant::now();
    merkle_root(bytes_vec.as_slice());
    elapsed("merkle", start.elapsed(), n);

    let mut vec = Vec::new();
    let start = Instant::now();
    for _ in 0..n {
        vec.push(Key::new().to_bytes());
    }
    elapsed("Init vector", start.elapsed(), n);

    let db = DB::open_default(&dir).unwrap();
    let start = Instant::now();
    let dummy = [0u8;16];
    for i in 0..n {
        match db.put(&vec[i],&dummy) {
            Ok(_) => (),
            Err(e) => println!("operational problem encountered: {}", e),
        }
    }
    elapsed("Random writes", start.elapsed(), n);

    let start = Instant::now();
    for i in 0..n {
        match db.get(&vec[i]) {
            Ok(Some(_)) => (),
            Ok(None) => println!("value not found"),
            Err(e) => println!("operational problem encountered: {}", e),
        }

    }
    elapsed("Random reads", start.elapsed(), n);

    let start = Instant::now();
    vec.sort();
    assert!(vec.windows(2).all(|w| w[0] <= w[1]));
    elapsed("Memory sort", start.elapsed(), n);

    dir.push_str("2");
    let db = DB::open_default(dir).unwrap();
    let start = Instant::now();
    let dummy = [0u8;16];
    for i in 0..n {
        match db.put(&vec[i],&dummy) {
            Ok(_) => (),
            Err(e) => println!("operational problem encountered: {}", e),
        }
    }
    elapsed("Ordered writes", start.elapsed(), n);

    let start = Instant::now();
    for i in 0..n {
        match db.get(&vec[i]) {
            Ok(Some(_)) => (),
            Ok(None) => println!("value not found"),
            Err(e) => println!("operational problem encountered: {}", e),
        }

    }
    elapsed("Ordered reads", start.elapsed(), n);

}

fn elapsed(title : &str, dur :Duration, n : usize ) {
    let secs : f64 = (dur.subsec_nanos() as f64 / 1_000_000_000f64)+dur.as_secs() as f64;
    println!("{:15} {:7.3}s {:12.2}tx/s",title, secs, n as f64 / secs);
}

/*
fn transform_u32_to_array_of_u8(x:u32) -> [u8;4] {
    let b1 : u8 = ((x >> 24) & 0xff) as u8;
    let b2 : u8 = ((x >> 16) & 0xff) as u8;
    let b3 : u8 = ((x >> 8) & 0xff) as u8;
    let b4 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4]
}
*/

fn transform_u64_to_array_of_u8(x:u64) -> [u8;8] {
    let b1 : u8 = ((x >> 56) & 0xff) as u8;
    let b2 : u8 = ((x >> 48) & 0xff) as u8;
    let b3 : u8 = ((x >> 40) & 0xff) as u8;
    let b4 : u8 = ((x >> 32) & 0xff) as u8;
    let b5 : u8 = ((x >> 24) & 0xff) as u8;
    let b6 : u8 = ((x >> 16) & 0xff) as u8;
    let b7 : u8 = ((x >> 8) & 0xff) as u8;
    let b8 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4, b5, b6, b7, b8]
}

/// Calculates merkle root for the whole block
/// See: https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
pub fn merkle_root(hash_list: &[[u8; 32]]) -> [u8; 32] {
    let n_hashes = hash_list.len();
    if n_hashes == 1 {
        return *hash_list.first().unwrap();
    }

    let double_sha256 = |a, b| sha256(&sha256(&merge_slices(a, b)));

    // Calculates double sha hash for each pair. If len is odd, last value is ignored.
    let mut hash_pairs = hash_list.chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| double_sha256(&c[0], &c[1]))
        .collect::<Vec<[u8; 32]>>();

    // If the length is odd, take the last hash twice
    if n_hashes % 2 == 1 {
        let last_hash = hash_list.last().unwrap();
        hash_pairs.push(double_sha256(last_hash, last_hash));
    }
    return merkle_root(&mut hash_pairs);
}


#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.input(data);
    hasher.result(&mut out);
    return out;
}


/// Simple slice merge
#[inline]
pub fn merge_slices(a: &[u8], b: &[u8]) -> Vec<u8> {
    [a, b].iter()
        .flat_map(|v| v.iter().cloned())
        .collect::<Vec<u8>>()
}
