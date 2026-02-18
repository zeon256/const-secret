# const-secret

[![Crates.io](https://img.shields.io/crates/v/const-secret)](https://crates.io/crates/const-secret)
[![Crates.io Downloads](https://img.shields.io/crates/d/const-secret)](https://crates.io/crates/const-secret)
[![Docs.rs](https://img.shields.io/docsrs/const-secret)](https://docs.rs/const-secret)
[![License](https://img.shields.io/badge/license-Apache--2.0%2FMIT-blue)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85.1-orange)](https://blog.rust-lang.org/)
[![Rust Edition](https://img.shields.io/badge/Rust-2024-blue)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![no_std](https://img.shields.io/badge/no__std-compatible-success)](https://docs.rust-embedded.org/book/intro/no-std.html)

A compile-time constant encryption library for Rust with pluggable drop strategies and multiple algorithms.

## Motivation

A lot of the static or const string libraries make use of heavy macros which I don't like lol.

## Features

- **Compile-time encryption**: Secrets are encrypted at compile time; plaintext never appears in the binary.
- **Multiple algorithms**:
  - **XOR** — Simple, fast single-byte XOR (best for basic obfuscation).
  - **RC4** — Stream cipher with variable-length keys (1-256 bytes) for slightly better obfuscation.
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

### RC4 Algorithm (variable-length keys)

RC4 is a stream cipher that supports keys from 1 to 256 bytes. **Note:** RC4 is cryptographically broken; use only for obfuscation purposes.

```rust
use const_secret::{Encrypted, StringLiteral};
use const_secret::drop_strategy::Zeroize;
use const_secret::rc4::Rc4;

const KEY: [u8; 16] = *b"my-secret-key!!";

const SECRET: Encrypted<Rc4<16, Zeroize<[u8; 16]>>, StringLiteral, 6> =
    Encrypted::<Rc4<16, Zeroize<[u8; 16]>>, StringLiteral, 6>::new(*b"rc4sec", KEY);

fn main() {
    let plaintext: &str = &*SECRET;
    println!("{}", plaintext);  // prints: rc4sec
}
```

#### RC4 with ReEncrypt

```rust
use const_secret::{Encrypted, ByteArray};
use const_secret::rc4::{Rc4, ReEncrypt};

const KEY: [u8; 8] = *b"rc4key!!";

const DATA: Encrypted<Rc4<8, ReEncrypt<8>>, ByteArray, 10> =
    Encrypted::<Rc4<8, ReEncrypt<8>>, ByteArray, 10>::new(*b"sensitive!", KEY);
```

## How it works

1. **Compile-time encryption**: `Encrypted::new()` encrypts plaintext at compile time using the selected algorithm:
   - **XOR**: XORs each byte with the single-byte key.
   - **RC4**: Runs the Key Scheduling Algorithm (KSA) to initialize the S-box, then the Pseudo-Random Generation Algorithm (PRGA) to generate a keystream and XOR with plaintext.
   The ciphertext is stored in the binary; plaintext never appears.
2. **Lazy decryption**: `Deref` checks an atomic one-time flag:
   - First successful check sets the flag and decrypts ciphertext -> plaintext in place,
   - Later derefs skip re-decryption and return plaintext directly.
3. **Drop**: selected `DropStrategy` runs:
   - `Zeroize`: secure overwrite via `zeroize`,
   - `ReEncrypt`: re-encrypts plaintext back to ciphertext,
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

- **Not cryptographically secure**: Both XOR and RC4 provide obfuscation, not encryption. RC4 is cryptographically broken. Use this library for compile-time constant storage with defense-in-depth layering, not as a standalone encryption scheme.

- **Memory observability**: This library does not protect against memory-reading attacks. Once a secret is decrypted and in scope, an attacker with physical access (e.g., cold-boot attack), debugger access, or memory-disclosure vulnerabilities can observe the plaintext in RAM. Even `Zeroize` and `ReEncrypt` only clean up *after* the value is dropped—the plaintext remains observable while the value is live and dereferenced.
  
  **This is by design.** The library's goal is to prevent secrets from being embedded in the static binary, not to provide runtime memory protection. If you need defense against memory-reading attacks, consider:
  - Using trusted execution environments (TEEs) or secure enclaves
  - Minimizing plaintext lifetime and reducing the number of copies in memory
  - Encrypting sensitive data at rest and only decrypting on demand
  - Layering `Zeroize`/`ReEncrypt` with your own memory-access controls
  
  Use this library as part of a defense-in-depth strategy, not as a standalone guarantee.

## Choosing an Algorithm

| Algorithm | Speed | Key Size | Use Case |
|-----------|-------|----------|----------|
| **XOR** | Fastest | Single byte (0-255) | Speed-critical, simple obfuscation |
| **RC4** | Medium | 1-256 bytes | Variable key length, slightly better obfuscation |

**Recommendation**: Use XOR for most cases—it's faster and simpler. Use RC4 only if you need variable-length keys for some reason. 

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
