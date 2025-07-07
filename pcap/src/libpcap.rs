use std::fmt::{self, Display};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use libpcap::{Active, Capture, Device, PacketCodec, PacketStream};
use nix::net::if_::if_nametoindex;
use thiserror::Error;
use tokio_stream::StreamExt;

use super::{DataLinkReceiver, DataLinkSender, Pcap};
use crate::Channel;

/// PacketCodec implementation for converting packets to byte arrays
pub struct BoxCodec;

impl PacketCodec for BoxCodec {
    type Item = Box<[u8]>;

    fn decode(&mut self, packet: libpcap::Packet) -> Self::Item {
        packet.data.into()
    }
}

#[derive(Debug, PartialEq, Eq, Error)]
pub struct PcapError {
    inner: libpcap::Error,
}
impl Clone for PcapError {
    fn clone(&self) -> Self {
        Self {
            inner: match &self.inner {
                libpcap::Error::MalformedError(utf8_error) => {
                    libpcap::Error::MalformedError(*utf8_error)
                }
                libpcap::Error::InvalidString => libpcap::Error::InvalidString,
                libpcap::Error::PcapError(err) => libpcap::Error::PcapError(err.clone()),
                libpcap::Error::InvalidLinktype => libpcap::Error::InvalidLinktype,
                libpcap::Error::TimeoutExpired => libpcap::Error::TimeoutExpired,
                libpcap::Error::NoMorePackets => libpcap::Error::NoMorePackets,
                libpcap::Error::NonNonBlock => libpcap::Error::NonNonBlock,
                libpcap::Error::InsufficientMemory => libpcap::Error::InsufficientMemory,
                libpcap::Error::InvalidInputString => libpcap::Error::InvalidInputString,
                libpcap::Error::IoError(error_kind) => libpcap::Error::IoError(*error_kind),
                libpcap::Error::InvalidRawFd => libpcap::Error::InvalidRawFd,
                libpcap::Error::ErrnoError(errno) => libpcap::Error::ErrnoError(*errno),
                libpcap::Error::BufferOverflow => libpcap::Error::BufferOverflow,
            },
        }
    }
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
#[async_trait]
impl DataLinkSender for LibpcapDataLinkSender {
    async fn send_bytes(&mut self, buf: &[u8]) -> Result<(), PcapError> {
        let capture = self.capture.clone();
        let buf = buf.to_vec();
        tokio::task::spawn_blocking(move || {
            capture
                .lock()
                .expect("failed to lock capture")
                .sendpacket(buf)
                .map_err(PcapError::from)
        })
        .await
        .expect("spawn_blocking failed")
    }
}

pub struct LibpcapDataLinkReceiver {
    stream: PacketStream<Active, BoxCodec>,
}

// PacketStreamはCloneできないため、LibpcapDataLinkReceiverもClone不可
#[async_trait]
impl DataLinkReceiver for LibpcapDataLinkReceiver {
    async fn recv(&mut self) -> Result<Vec<u8>, PcapError> {
        // Get next packet from stream
        match self.stream.next().await {
            Some(packet_data) => match packet_data {
                Ok(data) => Ok(data.to_vec()),
                Err(e) => Err(PcapError::from(e)),
            },
            None => Err(PcapError::from(libpcap::Error::NoMorePackets)),
        }
    }
}
pub struct NetworkInterface {
    index: u32,
    name: String,
}
impl NetworkInterface {
    pub fn new(index: u32, name: String) -> Self {
        Self { index, name }
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn list() -> Result<Vec<NetworkInterface>, PcapError> {
        let devices = Device::list().map_err(PcapError::from)?;
        let interfaces = devices
            .iter()
            .map(|device| {
                // libpcap側でインターフェースを取得できているのでindexが存在しないことはない
                let index =
                    if_nametoindex(device.name.as_str()).expect("Failed to get interface index");

                Ok(NetworkInterface {
                    name: device.name.clone(),
                    index,
                })
            })
            .collect::<Result<Vec<_>, PcapError>>()?;
        Ok(interfaces)
    }

    pub fn find_by_name<S: AsRef<str>>(name: S) -> Option<NetworkInterface> {
        Self::list()
            .ok()?
            .into_iter()
            .find(|ni| ni.name == name.as_ref())
    }
}
impl Pcap for NetworkInterface {
    fn open(&self, promisc: bool) -> Result<super::Channel, PcapError> {
        let capture = Capture::from_device(self.name().as_str())
            .map_err(PcapError::from)?
            .immediate_mode(true)
            .promisc(promisc)
            .open()
            .map_err(PcapError::from)?
            .setnonblock()
            .map_err(PcapError::from)?;

        // Create stream for receiver
        let stream = capture.stream(BoxCodec).map_err(PcapError::from)?;

        // Create a new capture for sender (we need separate instances)
        let sender_capture = Capture::from_device(self.name().as_str())
            .map_err(PcapError::from)?
            .immediate_mode(true)
            .promisc(promisc)
            .open()
            .map_err(PcapError::from)?;

        let chan = Channel {
            sender: Box::new(LibpcapDataLinkSender {
                capture: Arc::new(Mutex::new(sender_capture)),
            }),
            receiver: Box::new(LibpcapDataLinkReceiver { stream }),
        };

        Ok(chan)
    }
}
