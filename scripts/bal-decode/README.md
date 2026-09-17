# BAL RLP decoding study

**Recommendation: retain the current general decoder.** Neither encoded BAL size nor the gas label provides a robust strategy threshold. Allocation pre-counting reduces memory traffic but slows both measured corpora. Short native-integer prototypes look promising in a custom BAL decoder; replacing only the shared RLP implementation reproduces much less of that improvement and regresses full-width native integer microbenchmarks. This contribution adds a reproducible benchmark and differential checks, with no production decoder or dependency change.

[Complete readable tables](results/tables.md) · [Every case/strategy, throughput, allocations and confidence interval](results/matrix.csv) · [Corpus provenance and counts](results/manifest.json) · [Raw results and profiles](results/)

## Measured results

September 16, 2026. Negative changes mean faster. Each corpus contains 30 distinct merged BALs. The initial comparison has 11 within-case repeats; intervals below are paired 95% t intervals on corpus means across repeat positions.

| Strategy | 200M: decode µs; change [95% CI] | 300M: decode µs; change [95% CI] |
|---|---:|---:|
| Current main | 628.5 | 876.6 |
| Exact item count | 665.6; +5.90% [5.62, 6.18] | 928.8; +5.95% [5.11, 6.80] |
| Encoded-size estimate | 657.0; +4.54% [3.93, 5.15] | 915.9; +4.49% [3.87, 5.10] |
| Count lists ≥256 bytes | 657.7; +4.65% [4.29, 5.01] | 912.9; +4.14% [3.53, 4.75] |
| Size/memory-bounded estimate | 658.1; +4.71% [4.19, 5.23] | 913.0; +4.16% [3.76, 4.55] |
| Single-byte native shortcut | 632.8; +0.69% [0.43, 0.96] | 884.0; +0.84% [0.34, 1.34] |
| Single-byte U256 shortcut | 634.4; +0.93% [0.55, 1.31] | 887.6; +1.25% [0.85, 1.65] |
| Estimate + both shortcuts | 643.1; +2.33% [1.65, 3.00] | 897.6; +2.40% [1.88, 2.92] |

Singleton and first-item adaptive allocation also lose: approximately 6–7% and 5%, respectively. The complete tables include the other combinations and the custom-decoder/no-policy control. That control alone is about 2% slower than the upstream derived decoder on real samples: custom-decoder results must not be attributed solely to the policy being tested.

The second prototype directly decodes canonical native integers with up to three payload bytes. It improves the custom BAL implementation by about 5% versus upstream, but that is **not** the effect of a shared dependency change. Three actual `alloy-rlp` patches were evaluated with the original BAL decoder, no counting allocator, and 15 alternating baseline/candidate process pairs:

| Shared implementation | 200M change [95% CI] | 300M change [95% CI] |
|---|---:|---:|
| Prefix match, advance by length | +0.11% [−1.33, +1.54] | +0.07% [−1.41, +1.55] |
| Prefix match, return matched remainder | −0.72% [−1.83, +0.39] | −1.15% [−2.01, −0.29] |
| Existing header parser, direct short-value construction | +1.78% [−0.63, +4.19] | +2.26% [+0.32, +4.20] |

For the best shared candidate, 300M decode changes from 859.5 to 849.5 µs; decode-plus-drop changes from 1,057.9 to 1,049.4 µs (paired −0.79%). The 200M decode interval includes no change. Fixed-value native microbenchmarks show substantial short-value gains but regress `u32::MAX` from about 2.56 to 3.10 ns and `u64::MAX` from 2.52 to 3.18 ns. U256 uses ruint's separate implementation and is essentially unchanged by these shared native-integer patches. These microbenchmarks are mechanism checks, not estimates of end-to-end gain.

The rejected patches and regression tests are retained under [variants](variants/). No dependency PR is proposed on this evidence; duplicating native integer parsing inside EIP-7928 would conceal the ownership and code-generation tradeoff.

## Which approach for which size?

Use current main for the measured 585–971 KB BALs, the 2×/4× scaled real shapes, and as the general-purpose default at every size. Do not select a decoder using gas or total encoded length alone.

| Workload | Actual encoded size | Count versus baseline | Recommendation |
|---|---:|---:|---|
| Few large accounts | 81.7 KB | about +27% | Current main |
| Many small accounts | 65.5 KB | −12.3% [−14.6, −10.0] | Counting is worth further shape-specific study |
| Many small accounts | 1.05 MB / 4.19 MB | −16.2% / −38.7% | Potential specialized memory/latency tradeoff; not a global threshold |
| Code-heavy | 1.03 MB / 4.18 MB | +2.4% / +1.7% | Current main |
| Read-heavy | 95.0 KB / 442.5 KB | +14.4% / +12.9% | Current main |
| Write-heavy | 149.1 KB / 598.5 KB | +11.3% / +13.1% | Current main |
| Tiny structural samples | 28 B–4.2 KB | mixed | No stable threshold; timer/code-layout effects matter |

Counting's wins on large many-small-account shapes are real within this experiment, but a count pass alone does not validate record bodies. It can allocate excessively for a large list of invalid records. The exact-count variant is an experiment on validated corpora, **not a decoder for untrusted callers**. A deployable shape-specific policy would require its own allocation budget and independent workload validation; it is not implemented here.

### Allocation and gas bounds

Mean allocator requests include reallocations; allocated bytes are the sum of requested sizes, not live bytes or RSS:

| Corpus | Baseline calls / bytes | Count calls / bytes |
|---|---:|---:|
| 200M | 11,913 / 5,029,791 | 10,872 / 1,740,354 |
| 300M | 16,338 / 6,797,231 | 14,856 / 2,411,715 |

Counting saves roughly 65% of requested bytes, but adds a traversal. The estimate divides payload bytes by 160 for accounts, 48 for changed slots, 12 for storage histories, 32 for reads, 16 for balances, 8 for nonces and 64 for code changes. Size estimates cap initial capacity at 4,096 elements per list; the memory-bounded variant uses `min(payload_bytes / size_of::<T>(), 4096)`. Header parsing validates that the advertised payload is present before either estimate allocates. No allocation is based on an untrusted gas claim.

`Decodable::decode(&mut &[u8])` receives no gas limit. `Bal::validate_gas_limit` is a separate check on an already-decoded BAL. A caller could impose a separately validated limit, but silently introducing that dependency into a general RLP decoder would change its contract. Gas-bound allocation is therefore not an applicable decoder variant at this boundary.

## Corpus and provenance

- EIPs main: `c66a2fab30d24e2a2a584e2a48019faa5f6938af`, `crates/eip7928`, package 0.4.11; repository ownership verified through its workspace metadata and upstream remote.
- RLP main for dependency-only comparisons: `cf324cbcc4aeaba563f6321b2a752e71f9feec08`. Initial experiments use published alloy-rlp 0.3.16. Dependencies include alloy-primitives 1.7.3 and ruint 1.20.1; the standalone benchmark lockfile is retained.
- [200M source run](https://github.com/paradigmxyz/reth/actions/runs/35126507171): 30 BALs, 585,424–734,806 bytes, actual gas used 200,208,276–251,211,470.
- [300M source run](https://github.com/paradigmxyz/reth/actions/runs/35151583457): 30 BALs, 799,048–970,600 bytes, actual gas used 300,519,710–346,648,796.

Both `bench-raw-results` artifacts were available when checked. Input files are `txgen-payloads/measured-big-blocks.ndjson`; source SHA-256, sample hash, block number, actual gas, transaction count, environment count, encoded size, account/slot/change counts and maximum index are recorded in the manifest. The corpus is about 68 MB of raw RLP and is deliberately excluded from Git. Four small fixtures are included.

These real samples concatenate execution environments. Their index space includes the system phases of each environment: the recorded bound is `transaction_count + 2 * environment_count - 1`, rather than the single-environment `transaction_count + 1`. Transaction counts were cross-checked against the source payload transaction arrays. The measured bytes are never normalized or relabeled as single-block consensus fixtures.

The 28 synthetic cases structurally select accounts from, or replicate the decoded first 300M BAL, plus controlled read/write/code and many-small-account shapes. Every synthetic account gets a unique ordered address. Slots and changes remain ordered and unique; copied account histories retain their indices on a shared synthetic timeline. The manifest supplies a synthetic transaction count equal to the highest retained index, sufficient for all positive indices to denote synthetic transactions; it does not claim execution validity or measured gas. Code blobs are at most 24,000 bytes. RLP is canonically re-encoded after construction, never byte-truncated or concatenated. Names containing a target size are generator labels; use the manifest's **actual byte length**, especially for compact integer slots and indivisible large accounts.

## Measurement and profiling

All compilation and measurements ran on `ubuntu@dev-mattsse` in an isolated directory. AMD EPYC 4585PX, 16 cores/32 threads, SMT enabled, CPU affinity 8 (SMT sibling 24); Linux 6.8.0-110; rustc 1.96.1 / LLVM 22.1.2; glibc 2.39 system allocator; Cargo release optimization with debug level 1, default target CPU, no LTO or custom RUSTFLAGS. Governor `powersave`; boost state was not exposed by the queried sysfs path. Other Reth/Lighthouse services remained running; observed load was roughly 2–3. [Environment](results/profiles/environment.txt) records details. This is not an isolated bare-metal experiment, and differs from earlier Reth's jemalloc/SMT-disabled trace environment.

The timed result is `Vec<AccountChanges>`, the payload path used by `Bal`'s transparent `RlpDecodableWrapper`. Raw-BAL ownership/cache setup, hashing and Alloy-to-revm conversion are excluded. Files, hex conversion, structural construction, equivalence assertions, allocation counting and three warmup decodes are outside the timed region. Decode-only uses one clock interval per operation and drops the result afterwards. Lifecycle times a batch including drop. Results are passed through `black_box`. Iterations are `clamp(8, 2000, 8_000_000 / encoded_bytes)` per cell. The initial stage rotates strategy order; the historical five-strategy follow-up used a fixed within-round order (a limitation). The dependency-only stages alternate process order in 15 pairs. The current harness rotates all strategy orders.

Initial/follow-up timing binaries contain a disabled counting-allocator branch; accounting runs enable it only for one untimed decode. Dependency-only binaries have no allocator wrapper. Zero allocation columns in those files mean **not measured**, not zero allocations. Do not compare absolute times across these stages as though they were paired. Intervals describe repeated execution of this fixed corpus on this host, not population-wide confidence or correction for exploratory multiple comparisons.

Perf uses the installed `/usr/lib/linux-tools/6.8.0-139-generic/perf` binary with sudo, without changing host settings. Five counter repeats and separate 999 Hz DWARF stack recordings ran after timing; each profile has approximately 4,000 samples with no lost samples. Profiles include lifecycle work, including frees. For the first 300M sample, over 2,000 operations:

| Prototype | Instructions | Branches | Branch misses | Cache misses | Elapsed |
|---|---:|---:|---:|---:|---:|
| Baseline | 34.13 B | 6.56 B | 97.0 M | 59.4 M | 2.053 s |
| Count | 38.90 B | 7.20 B | 101.3 M | 33.5 M | 2.268 s |
| Short-native custom decoder | 32.63 B | 6.07 B | 97.7 M | 58.3 M | 1.972 s |

Counting reduces cache misses yet executes more instructions and branches, consistent with its extra pass. Adaptive allocation also increases branch misses. Baseline sampled self time includes approximately 19% in ruint U256 decoding, with substantial allocation/vector work; inline attribution is not a precise subphase decomposition. These profiles explain prototypes, not the much smaller shared-patch result. Counter events are multiplexed at about 83%; see raw stat files for repeat uncertainty. RSS for the repeated single-sample process was about 7.0 MB baseline and 5.4 MB count, not an allocation peak for the whole corpus.

The [assembly excerpts](results/profiles/micro-rest-assembly.txt) show native short paths avoiding the baseline's variable-size padded copy and byte swap. The first shared version introduces a second bounds check when advancing by a matched length. Returning the already-matched remainder removes that check, but adds prefix tests before the generic fallback; full-width integer regressions remain. U256 is a separate implementation, so native microbenchmark gains cannot be transferred to it.

## Reproduce

Use an isolated checkout of the recorded EIPs commit and a suitable Rust toolchain. No paid services are needed.

```sh
# Optional retrieval; artifacts may expire. Preserve the directory layout below.
gh run download 35126507171 -R paradigmxyz/reth -n bench-raw-results -D /tmp/bal-source/35126507171
gh run download 35151583457 -R paradigmxyz/reth -n bench-raw-results -D /tmp/bal-source/35151583457

cd scripts/bal-decode
# Expect each run directory to contain txgen-payloads/ and baseline-1/report.json.
python3 extract.py /tmp/bal-source corpus
python3 synthetic.py corpus
python3 verify_corpus.py corpus
# Compare generated hashes against results/manifest.json before timing.

cd bench
cargo test --release
cargo test --release --features alloc-count
cargo run --release --bin bal-decode-study -- ../fixtures 2
cargo build --release --features alloc-count
# Counters are enabled for one untimed operation, then disabled for timing.
taskset -c 8 target/release/bal-decode-study ../corpus 11 > ../new-exploratory.csv
# Without the feature the allocator wrapper is completely absent.
cargo build --release
taskset -c 8 target/release/bal-decode-study ../corpus 15 > ../new-clean.csv
```

`STRATEGIES=baseline,count,native` selects a subset. The current harness's `native` handles up to three-byte values; [initial.rs](variants/initial.rs) preserves the first stage's single-byte-only experiment. To recreate that implementation, temporarily use it as `bench/src/main.rs` and build with the counting allocator. The recorded follow-up sources are the same short-native algorithm with singleton/adaptive policies; its fixed-order limitation is noted above.

To reproduce a shared change, clone RLP at the recorded commit, apply one `variants/rlp-*.patch`, and build the benchmark using `cargo build --release --config 'patch.crates-io.alloy-rlp.path="/absolute/path/to/rlp/crates/rlp"'`. Build the unmodified RLP checkout the same way and copy each resulting executable to a distinct filename. Alternate those binaries with `STRATEGIES=baseline`, collecting 15 pairs; do not time both simultaneously. `profile FILE.rlp baseline 4000` runs repeated lifecycle decoding for perf. The `integers` binary separately measures native u32/u64 and ruint U256; its fixed-value, fixed-order microbenchmarks should remain separate from corpus conclusions.

`python3 analyze.py` regenerates the committed tables/matrix from the compressed raw CSVs. Differential tests check complete decoded values, valid-input remainder equivalence, all truncations of a representative BAL, every one-byte mutation, 25,600 random malformed buffers, and integer canonicality/leading-zero cases. Shared-patch tests additionally compare exact errors and remaining input against the original implementation across all native widths, every one/two-byte buffer, 65,537 canonical integers, boundary values, overflows and truncated headers. The experimental BAL decoders promise acceptance/value equivalence; their cursor/error details on failure can differ from derives and they are not proposed as production replacements.
