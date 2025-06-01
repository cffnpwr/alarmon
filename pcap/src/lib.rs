#[cfg(feature = "libpcap")]
#[path = "./libpcap.rs"]
mod backend;

pub use backend::PcapError;

pub trait DataLinkSender {
    fn _send(&mut self, buf: &[u8]) -> Result<(), PcapError>;
}
pub trait DataLinkSenderExt: DataLinkSender {
    fn send(&mut self, buf: impl AsRef<[u8]>) -> Result<(), PcapError> {
        self._send(buf.as_ref())
    }
}
impl<T: DataLinkSender> DataLinkSenderExt for T {}
pub trait DataLinkReceiver {
    fn recv(&mut self) -> Result<Vec<u8>, PcapError>;
}

pub enum Channel {
    Ethernet(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>),
}

pub fn open(ni: &NetworkInterface, promisc: bool) -> Result<Channel, PcapError> {
    backend::open(ni, promisc)
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    name: String,
    description: String,
    index: u32,
}
impl NetworkInterface {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn list() -> Result<Vec<Self>, PcapError> {
        backend::NetworkInterfaceInner::list()
    }

    pub fn find_by_name<S: AsRef<str>>(name: S) -> Option<Self> {
        backend::NetworkInterfaceInner::find_by_name(name)
    }

    pub fn open(&self, promisc: bool) -> Result<Channel, PcapError> {
        backend::open(self, promisc)
    }
}
