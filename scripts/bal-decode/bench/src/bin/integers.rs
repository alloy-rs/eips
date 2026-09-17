use alloy_primitives::U256;
use alloy_rlp::{Decodable, Header};
use std::{hint::black_box, time::Instant};
#[inline(never)]
fn base32(b: &mut &[u8]) -> u32 {
    u32::decode(b).unwrap()
}
#[inline(never)]
fn base64(b: &mut &[u8]) -> u64 {
    u64::decode(b).unwrap()
}
#[inline(never)]
fn base256(b: &mut &[u8]) -> U256 {
    U256::decode(b).unwrap()
}
#[inline(never)]
fn short64(b: &mut &[u8]) -> u64 {
    match *b {
        [1..=127, rest @ ..] => {
            let v = b[0] as u64;
            *b = rest;
            v
        }
        [128, rest @ ..] => {
            *b = rest;
            0
        }
        [129, a, rest @ ..] if *a >= 128 => {
            *b = rest;
            *a as u64
        }
        [130, a, c, rest @ ..] if *a != 0 => {
            *b = rest;
            ((*a as u64) << 8) | *c as u64
        }
        [131, a, c, d, rest @ ..] if *a != 0 => {
            *b = rest;
            ((*a as u64) << 16) | ((*c as u64) << 8) | *d as u64
        }
        _ => base64(b),
    }
}
#[inline(never)]
fn short32(b: &mut &[u8]) -> u32 {
    let saved = *b;
    let n = short64(b);
    if n > u32::MAX as u64 {
        *b = saved;
        base32(b)
    } else {
        n as u32
    }
}
#[inline(never)]
fn short256(b: &mut &[u8]) -> U256 {
    if let Some(&x) = b.first() {
        if x > 0 && x < 128 {
            *b = &b[1..];
            return U256::from(x);
        }
        if x == 128 {
            *b = &b[1..];
            return U256::ZERO;
        }
    }
    base256(b)
}
#[inline(never)]
fn fold64(b: &mut &[u8]) -> u64 {
    let raw = Header::decode_bytes(b, false).unwrap();
    assert!(raw.len() <= 8 && raw.first() != Some(&0));
    raw.iter().fold(0, |n, x| (n << 8) | *x as u64)
}
fn time<T>(f: fn(&mut &[u8]) -> T, raw: &[u8]) -> u128 {
    let t = Instant::now();
    for _ in 0..500_000 {
        black_box(f(&mut black_box(raw)));
    }
    t.elapsed().as_nanos()
}
fn main() {
    println!("value,round,type,strategy,ns_per_500000");
    for n in [0, 1, 127, 128, 255, 256, 4096, 65535, 65536, u32::MAX as u64, u64::MAX] {
        let raw = alloy_rlp::encode(n);
        for round in 0..11 {
            let mut variants = vec![
                ("u64", "baseline", time(base64, &raw)),
                ("u64", "short", time(short64, &raw)),
                ("u64", "fold", time(fold64, &raw)),
                ("U256", "baseline", time(base256, &raw)),
                ("U256", "single", time(short256, &raw)),
            ];
            if n <= u32::MAX as u64 {
                variants.push(("u32", "baseline", time(base32, &raw)));
                variants.push(("u32", "short", time(short32, &raw)));
            }
            for (ty, strategy, t) in variants {
                println!("{n},{round},{ty},{strategy},{t}");
            }
        }
    }
}
