# const-secret

A compile-time constant XOR encryption library for Rust with pluggable drop strategies.

## Motivation

A lot of the static or const string libraries make use of heavy macros which I don't like lol.

## Features

- **Compile-time encryption**: Secrets are XOR-encrypted at compile time; plaintext never appears in the binary.
- **Generic drop strategies**: Choose how the decrypted buffer is handled on drop:
  - `Zeroize` — Securely overwrite memory using the `zeroize` crate (vendor-approved).
  - `ReEncrypt<KEY>` — Re-encrypt the buffer back to ciphertext on drop.
  - `NoOp` — Leave the buffer as-is (for testing or when you have other guarantees).
- **Lazy decryption**: Decryption happens only when you dereference the value; the first dereference triggers decryption and sets a flag to prevent re-decryption.
- **`no_std` support**: Fully `no_std` compatible (requires only `core`).
- **StringLiteral and ByteArray modes**: Use `StringLiteral` to deref as `&str`, or `ByteArray` to deref as `&[u8; N]`.

## Usage

```rust
use const_secret::{Encrypted, Xor, ByteArray, StringLiteral};
use const_secret::drop_strategy::Zeroize;

const SECRET: Encrypted<Xor<0xAA, Zeroize>, StringLiteral, 5> =
    Encrypted::<Xor<0xAA, Zeroize>, StringLiteral, 5>::new(*b"hello");

fn main() {
    let plaintext: &str = &*SECRET;
    println!("{}", plaintext);  // prints: hello
}
```

When `SECRET` goes out of scope, the `Zeroize` drop strategy securely overwrites the decrypted buffer.

### Different Drop Strategies

#### Zeroize (recommended for production)

```rust
use const_secret::{Encrypted, Xor, ByteArray};
use const_secret::drop_strategy::Zeroize;

const API_KEY: Encrypted<Xor<0x42, Zeroize>, ByteArray, 16> =
    Encrypted::<Xor<0x42, Zeroize>, ByteArray, 16>::new(*b"supersecretkey!!");
```

#### ReEncrypt (re-encrypts on drop)

```rust
use const_secret::{Encrypted, Xor, StringLiteral};
use const_secret::xor::ReEncrypt;

const PASSWORD: Encrypted<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 8> =
    Encrypted::<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 8>::new(*b"password");
```

#### NoOp (no cleanup; use with caution)

```rust
use const_secret::{Encrypted, Xor, ByteArray};
use const_secret::drop_strategy::NoOp;

const TEST_DATA: Encrypted<Xor<0xCC, NoOp>, ByteArray, 4> =
    Encrypted::<Xor<0xCC, NoOp>, ByteArray, 4>::new([1, 2, 3, 4]);
```

## How it works

1. **Compile-time encryption**: `Encrypted::new()` XORs plaintext with key at compile time, storing ciphertext in the binary.
2. **Lazy decryption**: `Deref` checks an atomic one-time flag:
   - first successful check sets the flag and XORs ciphertext -> plaintext,
   - later derefs skip re-XOR and return plaintext directly.
3. **Drop**: selected `DropStrategy` runs:
   - `Zeroize`: secure overwrite via `zeroize`,
   - `ReEncrypt<KEY>`: XOR plaintext back to ciphertext,
   - `NoOp`: no cleanup.

## Verification

<details>
<summary>Quick Checks (click to expand)</summary>

### 1) Verify plaintext is absent from the binary

```bash
cargo build --example debug_drop
strings target/debug/examples/debug_drop | grep -E "^(hello|world|secret|leaked)$"
# Expected: no output
```

### 2) Verify release assembly has atomic guard + XOR transforms

```bash
cargo build --example debug_drop --release
objdump -d target/release/examples/debug_drop | grep -Ei "cmpxchg|xorl|xorb|movaps|xorps|0xaaaaaaaa|0xbbbbbbbb|0xdddddddd|0xeeeeeeee"
```

Expected:
- `cmpxchg` (or equivalent atomic guard pattern),
- scalar XOR for short buffers (`xorl` + `xorb`),
- SIMD XOR for long buffers (`movaps` + `xorps`) when optimization chooses vectorization.

</details>

<details>
<summary>Detailed Verification</summary>

### A. Short payloads: expect scalar XOR (very common)

For short strings (like 5 bytes), optimized code typically uses:
- one 4-byte XOR immediate (`imm32`),
- one 1-byte XOR immediate (`imm8`).

Example pattern:

```assembly
test   %al,%al
jnz    ...
mov    $0x1,%cl
xor    %eax,%eax
lock cmpxchg %cl,offset(%rsp)
jnz    ...
xorl   $0xbbbbbbbb,(%rsp)
xorb   $0xbb,0x4(%rsp)
```

This means:
- one-time guard succeeds once,
- payload is transformed in place with minimal scalar instructions.

### B. Long payloads: SIMD may be emitted

With longer strings (e.g. the long `ReEncrypt<0xBB>` example in `examples/debug_drop.rs`), release builds may vectorize XOR into 16-byte chunks.

Quick grep:

```bash
cargo build --example debug_drop --release
objdump -d target/release/examples/debug_drop | grep -Ei "cmpxchg|movaps|xorps|0xbbbbbbbb"
```

Representative pattern:

```assembly
test   %al,%al
jnz    ...
lock cmpxchg %cl,offset(%rsp)
jnz    ...
movaps xmm0,[key_mask_0xbb]
movaps xmm1,[rsp+...]
xorps  xmm1,xmm0
movaps [rsp+...],xmm1
... repeated for additional 16-byte chunks ...
```

Notes:
- `xorps` is used as a bitwise XOR instruction on XMM registers.
- Exact mnemonics/registers/offsets vary by LLVM version, optimization level, and target CPU features.
- Seeing scalar in one build and SIMD in another is normal.

### C. Architecture notes

- **x86_64**: common to see `cmpxchg`, `xorl`/`xorb`, and for longer payloads `movaps`/`xorps`.
- **AArch64**: look for atomic primitives (`ldxr`/`stxr` loops or `cas*`) and `eor` vector/scalar ops.

AArch64 quick check:

```bash
cargo build --example debug_drop --release --target aarch64-unknown-linux-gnu
objdump -d target/aarch64-unknown-linux-gnu/release/examples/debug_drop | grep -Ei "ldxr|stxr|cas|eor|0xbb|0xaa|0xdd|0xee"
```

</details>

## Building

```bash
cargo build
cargo test
cargo build --example debug_drop
cargo run --example debug_drop
```

## Thread Safety

`Encrypted` is `Sync` and can be shared across threads:

- An atomic flag gates the first XOR/decrypt path.
- After first deref, concurrent reads are safe.
- Multiple threads can deref the same value concurrently.

## Caveats

- **XOR is not cryptographic encryption**: this is obfuscation/encoding for compile-time constant protection, not standalone cryptography.
- **Runtime memory observability**: once decrypted, plaintext can be visible in RAM while live. `Zeroize`/`ReEncrypt` only run on drop.

This is by design: the goal is to avoid embedding plaintext in static binaries. For stronger protection, combine with stricter runtime controls and defense-in-depth.

<details>
<summary>Example: Checking the Binary</summary>

```bash
cargo build --example debug_drop
strings target/debug/examples/debug_drop | grep -c hello
# Output: 0

cargo run --example debug_drop
# Output includes:
# [zeroize] decrypted: "hello"
# [reencrypt] decrypted: "world"
# [reencrypt-long] decrypted: "world-world-world-world-world-world-world-world-world-world-1234"
# [noop-derefed] decrypted: "leaked"
# [bytes-zeroize] decrypted: [de, ad, be, ef]
# done — all secrets dropped

cargo build --example debug_drop --release
objdump -d target/release/examples/debug_drop | grep -Ei "cmpxchg|movaps|xorps|xorl|xorb|0xaaaaaaaa|0xbbbbbbbb|0xdddddddd|0xeeeeeeee"
```

</details>

## License

Licensed under either of:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- **MIT license** ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
