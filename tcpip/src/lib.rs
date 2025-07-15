#![feature(const_trait_impl)]

pub mod address;
pub mod arp;
pub mod checksum;
pub mod ethernet;
pub mod icmp;
pub mod icmpv6;
pub mod ip_cidr;
pub mod ipv4;
pub mod ipv6;
#[cfg(target_os = "macos")]
pub mod loopback;

trait TryFromBytes {
    type Error;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
