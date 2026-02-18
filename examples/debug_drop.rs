use const_secret::{
    ByteArray, Encrypted, StringLiteral,
    drop_strategy::{NoOp, Zeroize},
    rc4::{Rc4, ReEncrypt as Rc4ReEncrypt},
    xor::{ReEncrypt, Xor},
};

const HELLO_ZEROIZE: Encrypted<Xor<0xAA, Zeroize>, StringLiteral, 5> =
    Encrypted::<Xor<0xAA, Zeroize>, StringLiteral, 5>::new(*b"hello");

const WORLD_REENCRYPT: Encrypted<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 5> =
    Encrypted::<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 5>::new(*b"world");

// Longer payload to encourage vectorized/SIMD XOR codegen in optimized builds.
const WORLD_REENCRYPT_LONG: Encrypted<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 64> =
    Encrypted::<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 64>::new(
        *b"world-world-world-world-world-world-world-world-world-world-1234",
    );

const SECRET_NOOP: Encrypted<Xor<0xCC, NoOp>, StringLiteral, 6> =
    Encrypted::<Xor<0xCC, NoOp>, StringLiteral, 6>::new(*b"secret");

const LEAKED_NOOP: Encrypted<Xor<0xDD, NoOp>, StringLiteral, 6> =
    Encrypted::<Xor<0xDD, NoOp>, StringLiteral, 6>::new(*b"leaked");

const BYTES_ZEROIZE: Encrypted<Xor<0xEE, Zeroize>, ByteArray, 4> =
    Encrypted::<Xor<0xEE, Zeroize>, ByteArray, 4>::new(*b"\xDE\xAD\xBE\xEF");

// RC4 examples
const RC4_KEY_5: [u8; 5] = *b"mykey";
const RC4_KEY_16: [u8; 16] = *b"sixteen-byte-key";

const RC4_ZEROIZE: Encrypted<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 5> =
    Encrypted::<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 5>::new(*b"rc4!0", RC4_KEY_5);

const RC4_NOOP: Encrypted<Rc4<16, NoOp<[u8; 16]>>, StringLiteral, 13> =
    Encrypted::<Rc4<16, NoOp<[u8; 16]>>, StringLiteral, 13>::new(*b"rc4-with-noop", RC4_KEY_16);

const RC4_BYTES: Encrypted<Rc4<5, Zeroize<[u8; 5]>>, ByteArray, 4> =
    Encrypted::<Rc4<5, Zeroize<[u8; 5]>>, ByteArray, 4>::new(*b"\x01\x02\x03\x04", RC4_KEY_5);

const RC4_REENCRYPT: Encrypted<Rc4<5, Rc4ReEncrypt<5>>, StringLiteral, 6> =
    Encrypted::<Rc4<5, Rc4ReEncrypt<5>>, StringLiteral, 6>::new(*b"secret", RC4_KEY_5);

fn print_addr<T>(label: &str, val: &T) {
    let ptr = val as *const T;
    let size = core::mem::size_of::<T>();
    eprintln!("[{label}] struct @ {ptr:?}  (size {size})");
}

fn main() {
    {
        let secret = HELLO_ZEROIZE;
        print_addr("zeroize", &secret);

        let plain: &str = &*secret;
        eprintln!("[zeroize] decrypted: {plain:?}");
    }

    eprintln!();

    {
        let secret = WORLD_REENCRYPT;
        print_addr("reencrypt", &secret);

        let plain: &str = &*secret;
        eprintln!("[reencrypt] decrypted: {plain:?}");
    }

    eprintln!();

    {
        let secret = WORLD_REENCRYPT_LONG;
        print_addr("reencrypt-long", &secret);

        let plain: &str = &*secret;
        eprintln!("[reencrypt-long] decrypted: {plain:?}");
    }

    eprintln!();

    {
        let secret = SECRET_NOOP;
        print_addr("noop-no-deref", &secret);
    }

    eprintln!();

    {
        let secret = LEAKED_NOOP;
        print_addr("noop-derefed", &secret);

        let plain: &str = &*secret;
        eprintln!("[noop-derefed] decrypted: {plain:?}");
    }

    eprintln!();

    {
        let secret = BYTES_ZEROIZE;
        print_addr("bytes-zeroize", &secret);

        let plain: &[u8; 4] = &*secret;
        eprintln!("[bytes-zeroize] decrypted: {plain:x?}");
    }

    eprintln!();

    // RC4 examples
    {
        let secret = RC4_ZEROIZE;
        print_addr("rc4-zeroize", &secret);

        let plain: &str = &*secret;
        eprintln!("[rc4-zeroize] decrypted: {plain:?}");
    }

    eprintln!();

    {
        let secret = RC4_NOOP;
        print_addr("rc4-noop", &secret);

        let plain: &str = &*secret;
        eprintln!("[rc4-noop] decrypted: {plain:?}");
    }

    eprintln!();

    {
        let secret = RC4_BYTES;
        print_addr("rc4-bytes", &secret);

        let plain: &[u8; 4] = &*secret;
        eprintln!("[rc4-bytes] decrypted: {plain:x?}");
    }

    eprintln!();

    {
        let secret = RC4_REENCRYPT;
        print_addr("rc4-reencrypt", &secret);

        let plain: &str = &*secret;
        eprintln!("[rc4-reencrypt] decrypted: {plain:?}");
    }

    eprintln!("done — all secrets dropped");
}
