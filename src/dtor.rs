use zeroize::Zeroize;

use crate::AlgorithmDtor;

pub struct NoOpDtor;
pub struct ZeroizeDtor;

impl AlgorithmDtor for NoOpDtor {
    fn drop<const N: usize>(_buf: &mut [u8; N]) {
        // No-op
    }
}

impl AlgorithmDtor for ZeroizeDtor {
    fn drop<const N: usize>(buf: &mut [u8; N]) {
        buf.zeroize();
    }
}
