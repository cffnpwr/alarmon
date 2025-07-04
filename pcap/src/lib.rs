use async_trait::async_trait;
#[cfg(feature = "libpcap")]
pub use libpcap::{NetworkInterface, PcapError};

#[cfg(feature = "libpcap")]
mod libpcap;

pub trait Pcap {
    fn open(&self, promisc: bool) -> Result<Channel, PcapError>;
}

#[async_trait]
pub trait DataLinkSender: Send {
    async fn send_bytes(&mut self, buf: &[u8]) -> Result<(), PcapError>;
}
#[async_trait]
pub trait DataLinkSenderExt: DataLinkSender {
    async fn send(&mut self, buf: impl AsRef<[u8]> + Send) -> Result<(), PcapError> {
        self.send_bytes(buf.as_ref()).await
    }
}
impl<T: DataLinkSender> DataLinkSenderExt for T {}
#[async_trait]
pub trait DataLinkReceiver: Send {
    async fn recv(&mut self) -> Result<Vec<u8>, PcapError>;
}

pub enum Channel {
    Ethernet(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>),
}
