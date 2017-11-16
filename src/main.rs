extern crate rocksdb;
extern crate rand;

use rocksdb::DB;
use rand::Rng;
use std::time::{Instant , Duration};

const  N: usize = 1_000_000;
const KEY_LENGTH: usize = 20;

fn main() {

    println!("Working with {} elements with key length {} bytes", N, KEY_LENGTH );

    let mut vec = Vec::new();
    let i = Instant::now();
    for i in 0..N {
        let r = random20();
        //println!("{:?}", r);
        vec.push(r);
    }
    elapsed("Init vector",i.elapsed());


    let db = DB::open_default("/tmp/storage").unwrap();
    let mut rng = rand::thread_rng();
    let i = Instant::now();
    let dummy = [0u8;4];
    for i in 0..N {
        db.put(&vec[i],&dummy);
    }
    elapsed("Random writes",i.elapsed());

    let i = Instant::now();
    for i in 0..N {
        match db.get(&vec[i]) {
            Ok(Some(value)) => (),
            Ok(None) => println!("value not found"),
            Err(e) => println!("operational problem encountered: {}", e),
        }

    }
    elapsed("Random reads",i.elapsed());
}

fn elapsed(title : &str, dur :Duration ) {
    let secs : f64 = (dur.subsec_nanos() as f64 / 1_000_000_000f64)+dur.as_secs() as f64;
    println!("{} {:6.3} s {:6.2} tx/s",title, secs, N as f64 / secs);
}

fn random20() -> [u8;20] {
    let mut bytes = [0u8;20];
    let mut rng = rand::thread_rng();
    for i in 0..20 {
        bytes[i] = rng.gen::<u8>();
    }
    bytes
}