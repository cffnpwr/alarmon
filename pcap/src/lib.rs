pub use libpcap::{NetworkInterface, PcapError, open};

#[cfg(feature = "libpcap")]
mod libpcap;

pub trait DataLinkSender {
    fn send_bytes(&mut self, buf: &[u8]) -> Result<(), PcapError>;
}
pub trait DataLinkSenderExt: DataLinkSender {
    fn send(&mut self, buf: impl AsRef<[u8]>) -> Result<(), PcapError> {
        self.send_bytes(buf.as_ref())
    }
}
impl<T: DataLinkSender> DataLinkSenderExt for T {}
pub trait DataLinkReceiver {
    fn recv(&mut self) -> Result<Vec<u8>, PcapError>;
}

pub enum Channel {
    Ethernet(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>),
}
