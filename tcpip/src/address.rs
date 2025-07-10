pub trait SizedAddress {
    const BITS: u8;
}

#[const_trait]
pub trait IntoAddressType<T> {
    fn into_address_type() -> T;
}
