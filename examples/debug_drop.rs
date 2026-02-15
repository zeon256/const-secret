use const_secret::{
    drop_strategy::{NoOp, Zeroize},
    xor::{ReEncrypt, Xor},
    ByteArray, Encrypted, StringLiteral,
};

const HELLO_ZEROIZE: Encrypted<Xor<0xAA, Zeroize>, StringLiteral, 5> =
    Encrypted::<Xor<0xAA, Zeroize>, StringLiteral, 5>::new(*b"hello");

const WORLD_REENCRYPT: Encrypted<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 5> =
    Encrypted::<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 5>::new(*b"world");

const SECRET_NOOP: Encrypted<Xor<0xCC, NoOp>, StringLiteral, 6> =
    Encrypted::<Xor<0xCC, NoOp>, StringLiteral, 6>::new(*b"secret");

const LEAKED_NOOP: Encrypted<Xor<0xDD, NoOp>, StringLiteral, 6> =
    Encrypted::<Xor<0xDD, NoOp>, StringLiteral, 6>::new(*b"leaked");

const BYTES_ZEROIZE: Encrypted<Xor<0xEE, Zeroize>, ByteArray, 4> =
    Encrypted::<Xor<0xEE, Zeroize>, ByteArray, 4>::new(*b"\xDE\xAD\xBE\xEF");

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

    eprintln!("done — all secrets dropped");
}
