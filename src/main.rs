extern crate rocksdb;
extern crate rand;

use std::env;
use rocksdb::DB;
use rand::Rng;
use std::time::{Instant , Duration};

const  N: usize = 1_000_000;
const KEY_LENGTH: usize = 20;


fn main() {

    let default_dir = String::from("/tmp/storage");
    let dir = match env::args().nth(1) {
        Some(o) => o.parse::<String>().unwrap_or(default_dir),
        None => default_dir,
    };

    let n = match env::args().nth(2) {
        Some(o) => o.parse::<usize>().unwrap_or(N) ,
        None => N,
    };

    let mut key_length = match env::args().nth(3) {
        Some(o) => o.parse::<usize>().unwrap_or(KEY_LENGTH),
        None => KEY_LENGTH,
    };
    if key_length>32 {
        key_length=32;
    }

    println!("DB: {} Working with {} elements with key length {} bytes", dir, n, key_length);

    let mut vec = Vec::new();
    let start = Instant::now();
    for _ in 0..n {
        let r = random();
        let mut data = Vec::from(&r[..key_length]);
        vec.push(data);
    }
    elapsed("Init vector", start.elapsed());


    let db = DB::open_default(dir).unwrap();
    let mut rng = rand::thread_rng();
    let start = Instant::now();
    let dummy = [0u8;4];
    for i in 0..n {
        db.put(&vec[i],&dummy);
    }
    elapsed("Random writes", start.elapsed());

    let start = Instant::now();
    for i in 0..n {
        match db.get(&vec[i]) {
            Ok(Some(value)) => (),
            Ok(None) => println!("value not found"),
            Err(e) => println!("operational problem encountered: {}", e),
        }

    }
    elapsed("Random reads", start.elapsed());
}

fn elapsed(title : &str, dur :Duration ) {
    let secs : f64 = (dur.subsec_nanos() as f64 / 1_000_000_000f64)+dur.as_secs() as f64;
    println!("{} {:6.3} s {:6.2} tx/s",title, secs, N as f64 / secs);
}

fn random() -> [u8;32] {
    let mut bytes = [0u8;32];
    let mut rng = rand::thread_rng();
    for i in 0..32 {
        bytes[i] = rng.gen::<u8>();
    }
    bytes
}