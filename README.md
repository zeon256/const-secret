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

## Verification

### Verify plaintext is absent from binary

Build the example and check that the plaintext strings don't appear:

```bash
cargo build --example debug_drop
strings target/debug/examples/debug_drop | grep -E "^(hello|world|secret|leaked)$"
# Should print nothing (plaintext is encrypted in the binary)
```

### Inspect drop strategies with a debugger

The release binary includes SIMD-optimized drop implementations. You can verify the actual XOR operations:

#### Debug build
```bash
cargo build --example debug_drop
objdump -d target/debug/examples/debug_drop | grep -A 20 "ReEncrypt.*drop"
```

Look for the XOR instruction pattern:
```asm
mov	w10, #0xbb        ; load the key (0xBB for ReEncrypt)
eor	w8, w8, w10       ; XOR the byte
strb	w8, [x9]         ; store back
```

#### Release build (SIMD-optimized)
```bash
cargo build --example debug_drop --release
objdump -d target/release/examples/debug_drop | grep -B 5 -A 5 "movi.4h.*0xbb"
```

Look for SIMD XOR operations:
```asm
movi.4h	v1, #0xbb       ; load 0xBB into vector register
eor.8b	v0, v0, v1      ; XOR 4 bytes at once
eor	w8, w8, #0xbbbbbbbb ; XOR remaining byte
```

### Run under debugger

Step through the drop implementations to observe the actual memory transformations:

```bash
cargo build --example debug_drop
lldb target/debug/examples/debug_drop

# Set breakpoints on drop implementations
(lldb) b const_secret::Encrypted::drop
(lldb) run

# When stopped, inspect the buffer
(lldb) frame variable secret
(lldb) memory read -count 5 &secret
```

## How it works

1. **Compile-time encryption**: The `Encrypted::new()` const function XORs the plaintext with the key, storing only the ciphertext in the binary.

2. **Lazy decryption**: The `Deref` impl checks an `AtomicBool` flag. On the first dereference:
   - If the flag is false, it atomically sets it to true and XORs the buffer again (ciphertext XOR key = plaintext).
   - Subsequent dereferences return the plaintext without re-XORing.

3. **Drop**: When the `Encrypted` value is dropped, the associated `DropStrategy` is invoked:
   - `Zeroize`: Uses the `zeroize` crate to securely overwrite.
   - `ReEncrypt<KEY>`: XORs the plaintext with the key to restore the ciphertext.
   - `NoOp`: Does nothing.

## Building

```bash
cargo build
cargo test
cargo build --example debug_drop
cargo run --example debug_drop
```

## Caveats

- **Single-threaded use only**: The `Encrypted` struct is not `Sync` due to `UnsafeCell`. Use per-thread instances or wrap in a synchronization primitive if needed.
- **XOR is not a cryptographic algorithm**: XOR alone provides obfuscation, not encryption. Use this for compile-time constant storage with security-in-depth layering, not as a standalone encryption scheme.
- **Memory observability**: Even with `Zeroize` or `ReEncrypt`, a memory-reading attacker (e.g., via cold-boot attack or debugger) can observe the plaintext while the value is in scope and dereferenced.

## Example: Checking the Binary

Run the provided example and verify the plaintext is not embedded:

```bash
cargo build --example debug_drop
strings target/debug/examples/debug_drop | grep -c hello
# Output: 0 (no matches—plaintext is encrypted)

cargo run --example debug_drop
# Output:
# [zeroize] struct @ 0x...  (size 6)
# [zeroize] decrypted: "hello"
# 
# [reencrypt] struct @ 0x...  (size 6)
# [reencrypt] decrypted: "world"
# 
# [noop-no-deref] struct @ 0x...  (size 7)
# 
# [noop-derefed] struct @ 0x...  (size 7)
# [noop-derefed] decrypted: "leaked"
# 
# [bytes-zeroize] struct @ 0x...  (size 5)
# [bytes-zeroize] decrypted: [de, ad, be, ef]
# done — all secrets dropped
```

Then disassemble to see the drop strategies in action:

```bash
objdump -d target/debug/examples/debug_drop | grep -A 50 "ReEncrypt.*drop"
```

The objdump output will show the XOR instructions being inlined by the compiler.

## License

Licensed under either of:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- **MIT license** ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
