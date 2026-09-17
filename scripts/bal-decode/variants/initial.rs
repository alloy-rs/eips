use alloy_eip7928::{AccountChanges,SlotChanges,StorageChange,BalanceChange,NonceChange,CodeChange,BlockAccessIndex};
use alloy_primitives::{Address,Bytes,U256};
use alloy_rlp::{Decodable,Header,Error};
use std::{hint::black_box,time::Instant,alloc::{GlobalAlloc,Layout,System},sync::atomic::{AtomicBool,AtomicUsize,Ordering}};
static TRACK:AtomicBool=AtomicBool::new(false); static ALLOCS:AtomicUsize=AtomicUsize::new(0);static BYTES:AtomicUsize=AtomicUsize::new(0);
struct Alloc;
unsafe impl GlobalAlloc for Alloc {
 unsafe fn alloc(&self,l:Layout)->*mut u8 {if TRACK.load(Ordering::Relaxed){ALLOCS.fetch_add(1,Ordering::Relaxed);BYTES.fetch_add(l.size(),Ordering::Relaxed);}unsafe{System.alloc(l)}}
 unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}
 unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8 {if TRACK.load(Ordering::Relaxed){ALLOCS.fetch_add(1,Ordering::Relaxed);BYTES.fetch_add(n,Ordering::Relaxed);}unsafe{System.realloc(p,l,n)}}
}
#[global_allocator]static A:Alloc=Alloc;
type Res<T>=Result<T,Error>;
fn record<T>(b:&mut &[u8],f:impl FnOnce(&mut &[u8])->Res<T>)->Res<T>{let mut p=Header::decode_bytes(b,true)?;let n=p.len();let v=f(&mut p)?;if !p.is_empty(){return Err(Error::ListLengthMismatch{expected:n,got:n-p.len()})}Ok(v)}
fn list<T,const M:usize>(b:&mut &[u8],avg:usize,mut f:impl FnMut(&mut &[u8])->Res<T>)->Res<Vec<T>>{
 let mut p=Header::decode_bytes(b,true)?;
 let cap=match M {1=>count(p)?,2=> (p.len()/avg).min(4096),3=>if p.len()>=256{count(p)?}else{0},4=>(p.len()/std::mem::size_of::<T>().max(1)).min(4096),_=>0};
 let mut v=Vec::with_capacity(cap);while !p.is_empty(){v.push(f(&mut p)?)}Ok(v)
}
fn count(mut b:&[u8])->Res<usize>{let mut n=0;while !b.is_empty(){let h=Header::decode(&mut b)?;b=&b[h.payload_length..];n+=1;}Ok(n)}
#[inline]fn native<const I:bool>(b:&mut &[u8])->Res<u64>{if I {if let Some(&x)=b.first(){if x>0&&x<128{*b=&b[1..];return Ok(x as u64)}if x==128{*b=&b[1..];return Ok(0)}}}u64::decode(b)}
#[inline]fn wide<const I:bool>(b:&mut &[u8])->Res<U256>{if I{if let Some(&x)=b.first(){if x>0&&x<128{*b=&b[1..];return Ok(U256::from(x))}if x==128{*b=&b[1..];return Ok(U256::ZERO)}}}U256::decode(b)}
fn decode<const M:usize,const N:bool,const W:bool>(b:&mut &[u8])->Res<Vec<AccountChanges>>{list::<_,M>(b,160,|b|record(b,|b|Ok(AccountChanges{
 address:Address::decode(b)?,
 storage_changes:list::<_,M>(b,48,|b|record(b,|b|Ok(SlotChanges{slot:wide::<W>(b)?,changes:list::<_,M>(b,12,|b|record(b,|b|Ok(StorageChange{block_access_index:BlockAccessIndex(native::<N>(b)?),new_value:wide::<W>(b)?})))?})))?,
 storage_reads:list::<_,M>(b,32,wide::<W>)?,
 balance_changes:list::<_,M>(b,16,|b|record(b,|b|Ok(BalanceChange{block_access_index:BlockAccessIndex(native::<N>(b)?),post_balance:wide::<W>(b)?})))?,
 nonce_changes:list::<_,M>(b,8,|b|record(b,|b|Ok(NonceChange{block_access_index:BlockAccessIndex(native::<N>(b)?),new_nonce:native::<N>(b)?})))?,
 code_changes:list::<_,M>(b,64,|b|record(b,|b|Ok(CodeChange{block_access_index:BlockAccessIndex(native::<N>(b)?),new_code:Bytes::decode(b)?})))?,
})))}
type Decoder=fn(&mut &[u8])->Res<Vec<AccountChanges>>;
fn main(){
 let args:Vec<_>=std::env::args().collect();let dir=&args[1];let rounds:usize=args.get(2).map(|s|s.parse().unwrap()).unwrap_or(9);
 let strategies:Vec<(&str,Decoder)>=vec![("baseline",Vec::<AccountChanges>::decode),("manual",decode::<0,false,false>),("count",decode::<1,false,false>),("estimate",decode::<2,false,false>),("hybrid256",decode::<3,false,false>),("bounded",decode::<4,false,false>),("native",decode::<0,true,false>),("u256",decode::<0,false,true>),("integers",decode::<0,true,true>),("count_int",decode::<1,true,true>),("estimate_int",decode::<2,true,true>),("hybrid_int",decode::<3,true,true>)];
 let mut paths:Vec<_>=std::fs::read_dir(dir).unwrap().map(|e|e.unwrap().path()).filter(|p|p.extension().is_some_and(|x|x=="rlp")).collect();paths.sort();
 println!("id,bytes,round,strategy,decode_ns,lifecycle_ns,allocs,allocated_bytes");
 for path in paths{let raw=std::fs::read(&path).unwrap();let id=path.file_stem().unwrap().to_str().unwrap();let base=Vec::<AccountChanges>::decode(&mut raw.as_slice()).unwrap();
 for (_,f) in &strategies{assert_eq!(f(&mut raw.as_slice()).unwrap(),base);}
 let iters=(8_000_000/raw.len().max(1)).clamp(8,2000);
 for round in 0..rounds{for j in 0..strategies.len(){let (name,f)=strategies[(j+round*5)%strategies.len()];
 for _ in 0..3{black_box(f(&mut raw.as_slice()).unwrap());}
 ALLOCS.store(0,Ordering::Relaxed);BYTES.store(0,Ordering::Relaxed);TRACK.store(true,Ordering::Relaxed);let value=f(&mut raw.as_slice()).unwrap();TRACK.store(false,Ordering::Relaxed);drop(value);
 let (a,b)=(ALLOCS.load(Ordering::Relaxed),BYTES.load(Ordering::Relaxed));
 let mut elapsed=0;for _ in 0..iters{let t=Instant::now();let v=f(&mut black_box(raw.as_slice())).unwrap();black_box(&v);elapsed+=t.elapsed().as_nanos();drop(v);}
 let t=Instant::now();for _ in 0..iters{black_box(f(&mut black_box(raw.as_slice())).unwrap());}let life=t.elapsed().as_nanos();
 println!("{id},{},{round},{name},{},{},{a},{b}",raw.len(),elapsed/iters as u128,life/iters as u128);
 }}
 }
}
#[cfg(test)]mod tests{
use super::*;
#[test]fn differential(){
 let fs:[Decoder;8]=[decode::<0,false,false>,decode::<1,false,false>,decode::<2,false,false>,decode::<3,false,false>,decode::<4,false,false>,decode::<5,true,true>,decode::<6,true,true>,decode::<0,true,true>];
 let a=AccountChanges{address:Address::ZERO,storage_changes:vec![SlotChanges{slot:U256::from(128),changes:vec![StorageChange::new(BlockAccessIndex(256),U256::MAX)]}],storage_reads:vec![U256::ZERO,U256::from(127)],balance_changes:vec![BalanceChange::new(BlockAccessIndex(1),U256::from(256))],nonce_changes:vec![NonceChange::new(BlockAccessIndex(2),u64::MAX)],code_changes:vec![CodeChange{block_access_index:BlockAccessIndex(3),new_code:Bytes::from(vec![0;56])}]};
 let seed=alloy_rlp::encode(vec![a]);
 let check=|raw:&[u8]|{let mut input=raw;let base=Vec::<AccountChanges>::decode(&mut input);for f in fs {let mut b=raw;let got=f(&mut b);assert_eq!(got.is_ok(),base.is_ok(),"{raw:02x?}");if let (Ok(a),Ok(c))=(&base,&got){assert_eq!(a,c);assert_eq!(input,b);}}};
 check(&seed);for n in 0..seed.len(){check(&seed[..n]);}
 for i in 0..seed.len(){for byte in 0..=255{let mut raw=seed.clone();raw[i]=byte;check(&raw);}}
 let mut state=0xdeadbeef_u64;for len in 0..256{for _ in 0..100 {let raw:Vec<u8>=(0..len).map(|_|{state^=state<<13;state^=state>>7;state^=state<<17;state as u8}).collect();check(&raw);}}
}
#[test]fn integer_equivalence(){
 for n in 0..=65535u64{let raw=alloy_rlp::encode(n);let mut a=raw.as_slice();let mut b=a;assert_eq!(native::<true>(&mut a),u64::decode(&mut b));assert_eq!(a,b);let mut a=raw.as_slice();let mut b=a;assert_eq!(wide::<true>(&mut a),U256::decode(&mut b));assert_eq!(a,b);}
 for prefix in 0..=255{for len in 0..40{let mut raw=vec![prefix];raw.extend(vec![0;len]);let mut a=raw.as_slice();let mut b=a;assert_eq!(native::<true>(&mut a),u64::decode(&mut b));assert_eq!(a,b);let mut a=raw.as_slice();let mut b=a;assert_eq!(wide::<true>(&mut a),U256::decode(&mut b));assert_eq!(a,b);}}
}
}
