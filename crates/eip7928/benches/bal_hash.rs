//! Benchmarks for block access list hash computation.

use alloy_eip7928::{
    AccountChanges, BalanceChange, BlockAccessIndex, CodeChange, NonceChange, SlotChanges,
    StorageChange, compute_block_access_list_hash,
};
use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::Encodable;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn baseline_compute_block_access_list_hash(bal: &[AccountChanges]) -> alloy_primitives::B256 {
    let mut buf = Vec::new();
    alloy_rlp::encode_list(bal, &mut buf);
    alloy_primitives::keccak256(&buf)
}

fn address(index: usize) -> Address {
    let mut bytes = [0; 20];
    bytes[12..].copy_from_slice(&(index as u64).to_be_bytes());
    Address::from(bytes)
}

fn value(account: usize, item: usize) -> U256 {
    U256::from(((account as u64) << 32) | item as u64)
}

const fn block_access_index(account: usize, item: usize) -> BlockAccessIndex {
    BlockAccessIndex::new((account as u64).wrapping_mul(31).wrapping_add(item as u64))
}

fn make_bal(
    accounts: usize,
    storage_changes_per_account: usize,
    storage_reads_per_account: usize,
    balance_changes_per_account: usize,
    nonce_changes_per_account: usize,
    code_changes_per_account: usize,
) -> Vec<AccountChanges> {
    let mut bal = Vec::with_capacity(accounts);

    for account_index in 0..accounts {
        let mut account = AccountChanges::with_capacity(
            address(account_index),
            storage_changes_per_account
                .max(storage_reads_per_account)
                .max(balance_changes_per_account)
                .max(nonce_changes_per_account)
                .max(code_changes_per_account),
        );

        for slot_index in 0..storage_changes_per_account {
            account.storage_changes.push(SlotChanges::new(
                value(account_index, slot_index),
                vec![StorageChange::new(
                    block_access_index(account_index, slot_index),
                    value(account_index, slot_index + 1),
                )],
            ));
        }

        for read_index in 0..storage_reads_per_account {
            account.storage_reads.push(value(account_index, read_index + 128));
        }

        for balance_index in 0..balance_changes_per_account {
            account.balance_changes.push(BalanceChange::new(
                block_access_index(account_index, balance_index + 256),
                value(account_index, balance_index + 257),
            ));
        }

        for nonce_index in 0..nonce_changes_per_account {
            account.nonce_changes.push(NonceChange::new(
                block_access_index(account_index, nonce_index + 384),
                nonce_index as u64,
            ));
        }

        for code_index in 0..code_changes_per_account {
            account.code_changes.push(CodeChange::new(
                block_access_index(account_index, code_index + 512),
                Bytes::copy_from_slice(&[0x60, code_index as u8, 0x5f, 0x55]),
            ));
        }

        bal.push(account);
    }

    bal
}

fn encoded_len(bal: &[AccountChanges]) -> usize {
    let payload_length = bal.iter().map(Encodable::length).sum();
    payload_length + alloy_rlp::length_of_length(payload_length)
}

fn bench_hash(c: &mut Criterion) {
    let cases = [
        ("empty", Vec::new()),
        ("tiny", make_bal(1, 1, 1, 1, 1, 0)),
        ("regular_rpc_shape", make_bal(188, 1, 1, 1, 1, 0)),
        ("large_storage_heavy", make_bal(2_048, 8, 4, 2, 1, 0)),
        ("large_code_heavy", make_bal(512, 2, 2, 1, 1, 1)),
    ];

    let mut group = c.benchmark_group("compute_block_access_list_hash");
    for (name, bal) in &cases {
        assert_eq!(
            compute_block_access_list_hash(bal),
            baseline_compute_block_access_list_hash(bal)
        );
        group.throughput(Throughput::Bytes(encoded_len(bal) as u64));

        group.bench_with_input(BenchmarkId::new("baseline", name), bal, |b, bal| {
            b.iter(|| baseline_compute_block_access_list_hash(black_box(bal)));
        });

        group.bench_with_input(BenchmarkId::new("optimized", name), bal, |b, bal| {
            b.iter(|| compute_block_access_list_hash(black_box(bal)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hash);
criterion_main!(benches);
