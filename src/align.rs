#[repr(align(8))]
#[derive(Debug)]
pub struct Aligned8<E>(E);

#[repr(align(16))]
#[derive(Debug)]
pub struct Aligned16<E>(E);
