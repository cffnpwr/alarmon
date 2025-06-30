#![feature(const_trait_impl)]

pub mod address;
pub mod arp;
pub mod checksum;
pub mod ethernet;
pub mod icmp;
pub mod ip_cidr;
pub mod ipv4;

trait TryFromBytes {
    type Error;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
