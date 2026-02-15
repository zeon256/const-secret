use zeroize::Zeroize as ZeroizeTrait;

pub trait DropStrategy {
    fn drop(data: &mut [u8]);
}

pub struct Zeroize;
pub struct NoOp;

impl DropStrategy for Zeroize {
    fn drop(data: &mut [u8]) {
        data.zeroize();
    }
}

impl DropStrategy for NoOp {
    fn drop(_data: &mut [u8]) {}
}
