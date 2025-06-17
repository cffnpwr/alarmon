use std::fmt::{self, Display};
use std::sync::{Arc, Mutex};

use libpcap;
use libpcap::{Active, Capture, Device};
use nix::net::if_::if_nametoindex;

use super::{DataLinkReceiver, DataLinkSender, NetworkInterface};

#[derive(Debug)]
pub struct PcapError {
    inner: libpcap::Error,
}
impl From<libpcap::Error> for PcapError {
    fn from(value: libpcap::Error) -> Self {
        Self { inner: value }
    }
}
impl Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "libpcap error: {}", self.inner)
    }
}

#[derive(Clone)]
pub struct LibpcapDataLinkSender {
    capture: Arc<Mutex<Capture<Active>>>,
}
impl DataLinkSender for LibpcapDataLinkSender {
    fn send_bytes(&mut self, buf: &[u8]) -> Result<(), PcapError> {
        todo!()
    }
}

#[derive(Clone)]
pub struct LibpcapDataLinkReceiver {
    capture: Arc<Mutex<Capture<Active>>>,
}
impl DataLinkReceiver for LibpcapDataLinkReceiver {
    fn recv(&mut self) -> Result<Vec<u8>, PcapError> {
        self.capture
            .lock()
            .expect("failed to lock capture")
            .next_packet()
            .map_err(PcapError::from)
            .map(|packet| packet.data.to_vec())
    }
}

pub fn open(ni: &NetworkInterface, promisc: bool) -> Result<super::Channel, PcapError> {
    let capture = Capture::from_device(ni.name())
        .map_err(PcapError::from)?
        .promisc(promisc)
        .open()
        .map_err(PcapError::from)?;
    let capture = Arc::new(Mutex::new(capture));

    Ok(super::Channel::Ethernet(
        Box::new(LibpcapDataLinkSender {
            capture: capture.clone(),
        }),
        Box::new(LibpcapDataLinkReceiver {
            capture: capture.clone(),
        }),
    ))
}

pub(super) struct NetworkInterfaceInner;
impl NetworkInterfaceInner {
    pub(super) fn list() -> Result<Vec<NetworkInterface>, PcapError> {
        let devices = Device::list().map_err(PcapError::from)?;
        let interfaces = devices
            .iter()
            .map(|device| {
                // libpcap側でインターフェースを取得できているのでindexが存在しないことはない
                let index =
                    if_nametoindex(device.name.as_str()).expect("Failed to get interface index");

                Ok(NetworkInterface {
                    name: device.name.clone(),
                    description: device.desc.clone().unwrap_or_default(),
                    index,
                })
            })
            .collect::<Result<Vec<_>, PcapError>>()?;
        Ok(interfaces)
    }

    pub(super) fn find_by_name<S: AsRef<str>>(name: S) -> Option<super::NetworkInterface> {
        Self::list()
            .ok()?
            .into_iter()
            .find(|ni| ni.name == name.as_ref())
    }
}
