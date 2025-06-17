use std::fmt::{self, Display};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("Unsupported Protocol")]
    UnsupportedProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// IPv6 Hop-by-Hop Option
    /// ref: RFC8200
    HOPOPT = 0,

    /// Internet Control Message
    /// ref: RFC792
    ICMP = 1,

    /// Internet Group Management
    /// ref: RFC1112
    IGMP = 2,

    /// Gateway-to-Gateway
    /// ref: RFC823
    GGP = 3,

    /// IPv4 encapsulation
    /// ref: RFC2003
    IPv4 = 4,

    /// Stream
    /// ref: RFC1190, RFC1819
    ST = 5,

    /// Transmission Control
    /// ref: RFC9293
    TCP = 6,

    /// CBT
    CBT = 7,

    /// Exterior Gateway Protocol
    /// ref: RFC888
    EGP = 8,

    /// any private interior gateway (used by Cisco for their IGRP)
    IGP = 9,

    #[allow(non_camel_case_types)]
    /// BBN RCC Monitoring
    BBN_RCC_MON = 10,

    #[allow(non_camel_case_types)]
    /// Network Voice Protocol
    /// ref: RFC741
    NVP_II = 11,

    /// PUP
    PUP = 12,

    /// ARGUS
    ARGUS = 13,

    /// EMCON
    EMCON = 14,

    /// Cross Net Debugger
    XNET = 15,

    /// Chaos
    CHAOS = 16,

    /// User Datagram
    /// ref: RFC768
    UDP = 17,

    /// Multiplexing
    MUX = 18,

    #[allow(non_camel_case_types)]
    /// DCN Measurement Subsystems
    DCN_MEAS = 19,

    /// Host Monitoring
    /// ref: RFC869
    HMP = 20,

    /// Packet Radio Measurement
    PRM = 21,

    #[allow(non_camel_case_types)]
    /// XEROX NS IDP
    XNS_IDP = 22,

    /// Trunk-1
    TRUNK1 = 23,

    /// Trunk-2
    TRUNK2 = 24,

    /// Leaf-1
    LEAF1 = 25,

    /// Leaf-2
    LEAF2 = 26,

    /// Reliable Data Protocol
    /// ref: RFC908
    RDP = 27,

    /// Internet Reliable Transaction
    /// ref: RFC938
    IRTP = 28,

    #[allow(non_camel_case_types)]
    /// ISO Transport Protocol Class 4
    /// ref: RFC905
    ISO_TP4 = 29,

    /// Bulk Data Transfer Protocol
    /// ref: RFC969
    NETBLT = 30,

    #[allow(non_camel_case_types)]
    /// MFE Network Services Protocol
    MFE_NSP = 31,

    #[allow(non_camel_case_types)]
    /// MERIT Internodal Protocol
    MERIT_INP = 32,

    /// Datagram Congestion Control Protocol
    /// ref: RFC4340
    DCCP = 33,

    /// Third Party Connect Protocol
    ThreePC = 34,

    /// Inter-Domain Policy Routing Protocol
    IDPR = 35,

    /// XTP
    XTP = 36,

    /// Datagram Delivery Protocol
    DDP = 37,

    #[allow(non_camel_case_types)]
    /// IDPR Control Message Transport Proto
    IDPR_CMTP = 38,

    #[allow(non_camel_case_types)]
    /// TP++ Transport Protocol
    TP_PlusPlus = 39,

    /// IL Transport Protocol
    IL = 40,

    /// IPv6 encapsulation
    /// ref: RFC2473
    IPv6 = 41,

    /// Source Demand Routing Protocol
    SDRP = 42,

    /// Routing Header for IPv6
    IPv6Route = 43,

    /// Fragment Header for IPv6
    IPv6Frag = 44,

    /// Inter-Domain Routing Protocol
    IDRP = 45,

    /// Reservation Protocol
    /// ref: RFC2205, RFC3209
    RSVP = 46,

    /// Generic Routing Encapsulation
    /// ref: RFC2784
    GRE = 47,

    /// Dynamic Source Routing Protocol
    /// ref: RFC4728
    DSR = 48,

    /// BNA
    BNA = 49,

    /// Encap Security Payload
    /// ref: RFC4303
    ESP = 50,

    /// Authentication Header
    /// ref: RFC4302
    AH = 51,

    #[allow(non_camel_case_types)]
    /// Integrated Net Layer Security TUBA
    I_NLSP = 52,

    /// IP with Encryption
    SWIPE = 53,

    /// NBMA Address Resolution Protocol
    /// ref: RFC1735
    NARP = 54,

    /// Minimal IPv4 Encapsulation
    /// ref: RFC2004
    MinIPv4 = 55,

    /// Transport Layer Security Protocol using Kryptonet key management
    TLSP = 56,

    /// SKIP
    SKIP = 57,

    /// ICMP for IPv6
    /// ref: RFC8200
    IPv6ICMP = 58,

    /// No Next Header for IPv6
    /// ref: RFC8200
    IPv6NoNxt = 59,

    /// Destination Options for IPv6
    /// ref: RFC8200
    IPv6Opts = 60,

    #[allow(non_camel_case_types)]
    /// any host internal protocol
    HOST_INTERNAL = 61,

    /// CFTP
    CFTP = 62,

    #[allow(non_camel_case_types)]
    /// any local network
    LOCAL_NETWORK = 63,

    #[allow(non_camel_case_types)]
    /// SATNET and Backroom EXPAK
    SAT_EXPAK = 64,

    /// Kryptolan
    KRYPTOLAN = 65,

    /// MIT Remote Virtual Disk Protocol
    RVD = 66,

    /// Internet Pluribus Packet Core
    IPPC = 67,

    #[allow(non_camel_case_types)]
    /// any distributed file system
    DISTRIBUTED_FS = 68,

    #[allow(non_camel_case_types)]
    /// SATNET Monitoring
    SAT_MON = 69,

    /// VISA Protocol
    VISA = 70,

    /// Internet Packet Core Utility
    IPCV = 71,

    /// Computer Protocol Network Executive
    CPNX = 72,

    /// Computer Protocol Heart Beat
    CPHB = 73,

    /// Wang Span Network
    WSN = 74,

    /// Packet Video Protocol
    PVP = 75,

    #[allow(non_camel_case_types)]
    /// Backroom SATNET Monitoring
    BR_SAT_MON = 76,

    #[allow(non_camel_case_types)]
    /// SUN ND PROTOCOL-Temporary
    SUN_ND = 77,

    #[allow(non_camel_case_types)]
    /// WIDEBAND Monitoring
    WB_MON = 78,

    #[allow(non_camel_case_types)]
    /// WIDEBAND EXPAK
    WB_EXPAK = 79,

    #[allow(non_camel_case_types)]
    /// ISO Internet Protocol
    ISO_IP = 80,

    /// VMTP
    VMTP = 81,

    #[allow(non_camel_case_types)]
    /// SECURE-VMTP
    SECURE_VMTP = 82,

    /// VINES
    VINES = 83,

    /// Internet Protocol Traffic Manager
    IPTM = 84,

    #[allow(non_camel_case_types)]
    /// NSFNET-IGP
    NSFNET_IGP = 85,

    /// Dissimilar Gateway Protocol
    DGP = 86,

    /// TCF
    TCF = 87,

    /// EIGRP
    /// ref: RFC7868
    EIGRP = 88,

    /// OSPFIGP
    /// ref: RFC1583, RFC2328, RFC5340
    OSPFIGP = 89,

    /// Sprite RPC Protocol
    SpriteRPC = 90,

    /// Locus Address Resolution Protocol
    LARP = 91,

    /// Multicast Transport Protocol
    MTP = 92,

    /// AX.25 Frames
    AX25 = 93,

    /// IP-within-IP Encapsulation Protocol
    IPIP = 94,

    /// Mobile Internetworking Control Pro.
    MICP = 95,

    #[allow(non_camel_case_types)]
    /// Semaphore Communications Sec. Pro.
    SCC_SP = 96,

    /// Ethernet-within-IP Encapsulation
    /// ref: RFC3378
    ETHERIP = 97,

    /// Encapsulation Header
    /// ref: RFC1241
    ENCAP = 98,

    #[allow(non_camel_case_types)]
    /// any private encryption scheme
    PRIVATE_ENCRYPTION = 99,

    /// GMTP
    GMTP = 100,

    /// Ipsilon Flow Management Protocol
    IFMP = 101,

    /// PNNI over IP
    PNNI = 102,

    /// Protocol Independent Multicast
    /// ref: RFC7761
    PIM = 103,

    /// ARIS
    ARIS = 104,

    /// SCPS
    SCPS = 105,

    /// QNX
    QNX = 106,

    /// Active Networks
    AN = 107,

    /// IP Payload Compression Protocol
    /// ref: RFC2393
    IPComp = 108,

    /// Sitara Networks Protocol
    SNP = 109,

    /// Compaq Peer Protocol
    CompaqPeer = 110,

    /// IPX in IP
    IPXinIP = 111,

    /// Virtual Router Redundancy Protocol
    /// ref: RFC9568
    VRRP = 112,

    /// PGM Reliable Transport Protocol
    PGM = 113,

    #[allow(non_camel_case_types)]
    /// any 0-hop protocol
    ZERO_HOP = 114,

    /// Layer Two Tunneling Protocol
    /// ref: RFC3931
    L2TP = 115,

    /// D-II Data Exchange (DDX)
    DDX = 116,

    /// Interactive Agent Transfer Protocol
    IATP = 117,

    /// Schedule Transfer Protocol
    STP = 118,

    /// SpectraLink Radio Protocol
    SRP = 119,

    /// UTI
    UTI = 120,

    /// Simple Message Protocol
    SMP = 121,

    /// Simple Multicast Protocol
    SM = 122,

    /// Performance Transparency Protocol
    PTP = 123,

    #[allow(non_camel_case_types)]
    /// ISIS over IPv4
    ISIS_over_IPv4 = 124,

    /// FIRE
    FIRE = 125,

    /// Combat Radio Transport Protocol
    CRTP = 126,

    /// Combat Radio User Datagram
    CRUDP = 127,

    /// SSCOPMCE
    SSCOPMCE = 128,

    /// IPLT
    IPLT = 129,

    /// Secure Packet Shield
    SPS = 130,

    /// Private IP Encapsulation within IP
    PIPE = 131,

    /// Stream Control Transmission Protocol
    SCTP = 132,

    /// Fibre Channel
    /// ref: RFC6172
    FC = 133,

    #[allow(non_camel_case_types)]
    /// RSVP-E2E-IGNORE
    /// ref: RFC3175
    RSVP_E2E_IGNORE = 134,

    /// Mobility Header
    /// ref: RFC6275
    MobilityHeader = 135,

    /// UDPLite
    /// ref: RFC3828
    UDPLite = 136,

    #[allow(non_camel_case_types)]
    /// MPLS-in-IP
    /// ref: RFC4023
    MPLS_in_IP = 137,

    /// MANET Protocols
    /// ref: RFC5498
    MANET = 138,

    /// Host Identity Protocol
    /// ref: RFC7401
    HIP = 139,

    /// Shim6 Protocol
    /// ref: RFC5533
    Shim6 = 140,

    /// Wrapped Encapsulating Security Payload
    /// ref: RFC5840
    WESP = 141,

    /// Robust Header Compression
    /// ref: RFC5858
    ROHC = 142,

    /// Ethernet
    /// ref: RFC8986
    Ethernet = 143,

    /// AGGFRAG encapsulation payload for ESP
    /// ref: RFC9347
    AGGFRAG = 144,

    /// Network Service Header
    /// ref: RFC9491
    NSH = 145,

    /// Homa
    Homa = 146,

    #[allow(non_camel_case_types)]
    /// Bit-stream Emulation
    BIT_EMU = 147,

    /// Use for experimentation and testing
    /// ref: RFC3692
    Experimental253 = 253,

    /// Use for experimentation and testing
    /// ref: RFC3692
    Experimental254 = 254,

    /// Reserved
    Reserved = 255,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::HOPOPT => write!(f, "IPv6 Hop-by-Hop Option"),
            Protocol::ICMP => write!(f, "Internet Control Message Protocol"),
            Protocol::IGMP => write!(f, "Internet Group Management Protocol"),
            Protocol::GGP => write!(f, "Gateway-to-Gateway Protocol"),
            Protocol::IPv4 => write!(f, "IPv4 encapsulation"),
            Protocol::ST => write!(f, "Stream"),
            Protocol::TCP => write!(f, "Transmission Control Protocol"),
            Protocol::CBT => write!(f, "CBT"),
            Protocol::EGP => write!(f, "Exterior Gateway Protocol"),
            Protocol::IGP => write!(f, "any private interior gateway"),
            Protocol::BBN_RCC_MON => write!(f, "BBN RCC Monitoring"),
            Protocol::NVP_II => write!(f, "Network Voice Protocol"),
            Protocol::PUP => write!(f, "PUP"),
            Protocol::ARGUS => write!(f, "ARGUS"),
            Protocol::EMCON => write!(f, "EMCON"),
            Protocol::XNET => write!(f, "Cross Net Debugger"),
            Protocol::CHAOS => write!(f, "Chaos"),
            Protocol::UDP => write!(f, "User Datagram Protocol"),
            Protocol::MUX => write!(f, "Multiplexing"),
            Protocol::DCN_MEAS => write!(f, "DCN Measurement Subsystems"),
            Protocol::HMP => write!(f, "Host Monitoring"),
            Protocol::PRM => write!(f, "Packet Radio Measurement"),
            Protocol::XNS_IDP => write!(f, "XEROX NS IDP"),
            Protocol::TRUNK1 => write!(f, "Trunk-1"),
            Protocol::TRUNK2 => write!(f, "Trunk-2"),
            Protocol::LEAF1 => write!(f, "Leaf-1"),
            Protocol::LEAF2 => write!(f, "Leaf-2"),
            Protocol::RDP => write!(f, "Reliable Data Protocol"),
            Protocol::IRTP => write!(f, "Internet Reliable Transaction"),
            Protocol::ISO_TP4 => write!(f, "ISO Transport Protocol Class 4"),
            Protocol::NETBLT => write!(f, "Bulk Data Transfer Protocol"),
            Protocol::MFE_NSP => write!(f, "MFE Network Services Protocol"),
            Protocol::MERIT_INP => write!(f, "MERIT Internodal Protocol"),
            Protocol::DCCP => write!(f, "Datagram Congestion Control Protocol"),
            Protocol::ThreePC => write!(f, "Third Party Connect Protocol"),
            Protocol::IDPR => write!(f, "Inter-Domain Policy Routing Protocol"),
            Protocol::XTP => write!(f, "XTP"),
            Protocol::DDP => write!(f, "Datagram Delivery Protocol"),
            Protocol::IDPR_CMTP => write!(f, "IDPR Control Message Transport Proto"),
            Protocol::TP_PlusPlus => write!(f, "TP++ Transport Protocol"),
            Protocol::IL => write!(f, "IL Transport Protocol"),
            Protocol::IPv6 => write!(f, "IPv6 encapsulation"),
            Protocol::SDRP => write!(f, "Source Demand Routing Protocol"),
            Protocol::IPv6Route => write!(f, "Routing Header for IPv6"),
            Protocol::IPv6Frag => write!(f, "Fragment Header for IPv6"),
            Protocol::IDRP => write!(f, "Inter-Domain Routing Protocol"),
            Protocol::RSVP => write!(f, "Reservation Protocol"),
            Protocol::GRE => write!(f, "Generic Routing Encapsulation"),
            Protocol::DSR => write!(f, "Dynamic Source Routing Protocol"),
            Protocol::BNA => write!(f, "BNA"),
            Protocol::ESP => write!(f, "Encap Security Payload"),
            Protocol::AH => write!(f, "Authentication Header"),
            Protocol::I_NLSP => write!(f, "Integrated Net Layer Security TUBA"),
            Protocol::SWIPE => write!(f, "IP with Encryption"),
            Protocol::NARP => write!(f, "NBMA Address Resolution Protocol"),
            Protocol::MinIPv4 => write!(f, "Minimal IPv4 Encapsulation"),
            Protocol::TLSP => write!(
                f,
                "Transport Layer Security Protocol using Kryptonet key management"
            ),
            Protocol::SKIP => write!(f, "SKIP"),
            Protocol::IPv6ICMP => write!(f, "ICMP for IPv6"),
            Protocol::IPv6NoNxt => write!(f, "No Next Header for IPv6"),
            Protocol::IPv6Opts => write!(f, "Destination Options for IPv6"),
            Protocol::HOST_INTERNAL => write!(f, "any host internal protocol"),
            Protocol::CFTP => write!(f, "CFTP"),
            Protocol::LOCAL_NETWORK => write!(f, "any local network"),
            Protocol::SAT_EXPAK => write!(f, "SATNET and Backroom EXPAK"),
            Protocol::KRYPTOLAN => write!(f, "Kryptolan"),
            Protocol::RVD => write!(f, "MIT Remote Virtual Disk Protocol"),
            Protocol::IPPC => write!(f, "Internet Pluribus Packet Core"),
            Protocol::DISTRIBUTED_FS => write!(f, "any distributed file system"),
            Protocol::SAT_MON => write!(f, "SATNET Monitoring"),
            Protocol::VISA => write!(f, "VISA Protocol"),
            Protocol::IPCV => write!(f, "Internet Packet Core Utility"),
            Protocol::CPNX => write!(f, "Computer Protocol Network Executive"),
            Protocol::CPHB => write!(f, "Computer Protocol Heart Beat"),
            Protocol::WSN => write!(f, "Wang Span Network"),
            Protocol::PVP => write!(f, "Packet Video Protocol"),
            Protocol::BR_SAT_MON => write!(f, "Backroom SATNET Monitoring"),
            Protocol::SUN_ND => write!(f, "SUN ND PROTOCOL-Temporary"),
            Protocol::WB_MON => write!(f, "WIDEBAND Monitoring"),
            Protocol::WB_EXPAK => write!(f, "WIDEBAND EXPAK"),
            Protocol::ISO_IP => write!(f, "ISO Internet Protocol"),
            Protocol::VMTP => write!(f, "VMTP"),
            Protocol::SECURE_VMTP => write!(f, "SECURE-VMTP"),
            Protocol::VINES => write!(f, "VINES"),
            Protocol::IPTM => write!(f, "Internet Protocol Traffic Manager"),
            Protocol::NSFNET_IGP => write!(f, "NSFNET-IGP"),
            Protocol::DGP => write!(f, "Dissimilar Gateway Protocol"),
            Protocol::TCF => write!(f, "TCF"),
            Protocol::EIGRP => write!(f, "EIGRP"),
            Protocol::OSPFIGP => write!(f, "OSPFIGP"),
            Protocol::SpriteRPC => write!(f, "Sprite RPC Protocol"),
            Protocol::LARP => write!(f, "Locus Address Resolution Protocol"),
            Protocol::MTP => write!(f, "Multicast Transport Protocol"),
            Protocol::AX25 => write!(f, "AX.25 Frames"),
            Protocol::IPIP => write!(f, "IP-within-IP Encapsulation Protocol"),
            Protocol::MICP => write!(f, "Mobile Internetworking Control Pro."),
            Protocol::SCC_SP => write!(f, "Semaphore Communications Sec. Pro."),
            Protocol::ETHERIP => write!(f, "Ethernet-within-IP Encapsulation"),
            Protocol::ENCAP => write!(f, "Encapsulation Header"),
            Protocol::PRIVATE_ENCRYPTION => write!(f, "any private encryption scheme"),
            Protocol::GMTP => write!(f, "GMTP"),
            Protocol::IFMP => write!(f, "Ipsilon Flow Management Protocol"),
            Protocol::PNNI => write!(f, "PNNI over IP"),
            Protocol::PIM => write!(f, "Protocol Independent Multicast"),
            Protocol::ARIS => write!(f, "ARIS"),
            Protocol::SCPS => write!(f, "SCPS"),
            Protocol::QNX => write!(f, "QNX"),
            Protocol::AN => write!(f, "Active Networks"),
            Protocol::IPComp => write!(f, "IP Payload Compression Protocol"),
            Protocol::SNP => write!(f, "Sitara Networks Protocol"),
            Protocol::CompaqPeer => write!(f, "Compaq Peer Protocol"),
            Protocol::IPXinIP => write!(f, "IPX in IP"),
            Protocol::VRRP => write!(f, "Virtual Router Redundancy Protocol"),
            Protocol::PGM => write!(f, "PGM Reliable Transport Protocol"),
            Protocol::ZERO_HOP => write!(f, "any 0-hop protocol"),
            Protocol::L2TP => write!(f, "Layer Two Tunneling Protocol"),
            Protocol::DDX => write!(f, "D-II Data Exchange (DDX)"),
            Protocol::IATP => write!(f, "Interactive Agent Transfer Protocol"),
            Protocol::STP => write!(f, "Schedule Transfer Protocol"),
            Protocol::SRP => write!(f, "SpectraLink Radio Protocol"),
            Protocol::UTI => write!(f, "UTI"),
            Protocol::SMP => write!(f, "Simple Message Protocol"),
            Protocol::SM => write!(f, "Simple Multicast Protocol"),
            Protocol::PTP => write!(f, "Performance Transparency Protocol"),
            Protocol::ISIS_over_IPv4 => write!(f, "ISIS over IPv4"),
            Protocol::FIRE => write!(f, "FIRE"),
            Protocol::CRTP => write!(f, "Combat Radio Transport Protocol"),
            Protocol::CRUDP => write!(f, "Combat Radio User Datagram"),
            Protocol::SSCOPMCE => write!(f, "SSCOPMCE"),
            Protocol::IPLT => write!(f, "IPLT"),
            Protocol::SPS => write!(f, "Secure Packet Shield"),
            Protocol::PIPE => write!(f, "Private IP Encapsulation within IP"),
            Protocol::SCTP => write!(f, "Stream Control Transmission Protocol"),
            Protocol::FC => write!(f, "Fibre Channel"),
            Protocol::RSVP_E2E_IGNORE => write!(f, "RSVP-E2E-IGNORE"),
            Protocol::MobilityHeader => write!(f, "Mobility Header"),
            Protocol::UDPLite => write!(f, "UDPLite"),
            Protocol::MPLS_in_IP => write!(f, "MPLS-in-IP"),
            Protocol::MANET => write!(f, "MANET Protocols"),
            Protocol::HIP => write!(f, "Host Identity Protocol"),
            Protocol::Shim6 => write!(f, "Shim6 Protocol"),
            Protocol::WESP => write!(f, "Wrapped Encapsulating Security Payload"),
            Protocol::ROHC => write!(f, "Robust Header Compression"),
            Protocol::Ethernet => write!(f, "Ethernet"),
            Protocol::AGGFRAG => write!(f, "AGGFRAG encapsulation payload for ESP"),
            Protocol::NSH => write!(f, "Network Service Header"),
            Protocol::Homa => write!(f, "Homa"),
            Protocol::BIT_EMU => write!(f, "Bit-stream Emulation"),
            Protocol::Experimental253 => write!(f, "Use for experimentation and testing"),
            Protocol::Experimental254 => write!(f, "Use for experimentation and testing"),
            Protocol::Reserved => write!(f, "Reserved"),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(protocol: Protocol) -> Self {
        protocol as u8
    }
}

impl TryFrom<u8> for Protocol {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Protocol::HOPOPT),
            1 => Ok(Protocol::ICMP),
            2 => Ok(Protocol::IGMP),
            3 => Ok(Protocol::GGP),
            4 => Ok(Protocol::IPv4),
            5 => Ok(Protocol::ST),
            6 => Ok(Protocol::TCP),
            7 => Ok(Protocol::CBT),
            8 => Ok(Protocol::EGP),
            9 => Ok(Protocol::IGP),
            10 => Ok(Protocol::BBN_RCC_MON),
            11 => Ok(Protocol::NVP_II),
            12 => Ok(Protocol::PUP),
            13 => Ok(Protocol::ARGUS),
            14 => Ok(Protocol::EMCON),
            15 => Ok(Protocol::XNET),
            16 => Ok(Protocol::CHAOS),
            17 => Ok(Protocol::UDP),
            18 => Ok(Protocol::MUX),
            19 => Ok(Protocol::DCN_MEAS),
            20 => Ok(Protocol::HMP),
            21 => Ok(Protocol::PRM),
            22 => Ok(Protocol::XNS_IDP),
            23 => Ok(Protocol::TRUNK1),
            24 => Ok(Protocol::TRUNK2),
            25 => Ok(Protocol::LEAF1),
            26 => Ok(Protocol::LEAF2),
            27 => Ok(Protocol::RDP),
            28 => Ok(Protocol::IRTP),
            29 => Ok(Protocol::ISO_TP4),
            30 => Ok(Protocol::NETBLT),
            31 => Ok(Protocol::MFE_NSP),
            32 => Ok(Protocol::MERIT_INP),
            33 => Ok(Protocol::DCCP),
            34 => Ok(Protocol::ThreePC),
            35 => Ok(Protocol::IDPR),
            36 => Ok(Protocol::XTP),
            37 => Ok(Protocol::DDP),
            38 => Ok(Protocol::IDPR_CMTP),
            39 => Ok(Protocol::TP_PlusPlus),
            40 => Ok(Protocol::IL),
            41 => Ok(Protocol::IPv6),
            42 => Ok(Protocol::SDRP),
            43 => Ok(Protocol::IPv6Route),
            44 => Ok(Protocol::IPv6Frag),
            45 => Ok(Protocol::IDRP),
            46 => Ok(Protocol::RSVP),
            47 => Ok(Protocol::GRE),
            48 => Ok(Protocol::DSR),
            49 => Ok(Protocol::BNA),
            50 => Ok(Protocol::ESP),
            51 => Ok(Protocol::AH),
            52 => Ok(Protocol::I_NLSP),
            53 => Ok(Protocol::SWIPE),
            54 => Ok(Protocol::NARP),
            55 => Ok(Protocol::MinIPv4),
            56 => Ok(Protocol::TLSP),
            57 => Ok(Protocol::SKIP),
            58 => Ok(Protocol::IPv6ICMP),
            59 => Ok(Protocol::IPv6NoNxt),
            60 => Ok(Protocol::IPv6Opts),
            61 => Ok(Protocol::HOST_INTERNAL),
            62 => Ok(Protocol::CFTP),
            63 => Ok(Protocol::LOCAL_NETWORK),
            64 => Ok(Protocol::SAT_EXPAK),
            65 => Ok(Protocol::KRYPTOLAN),
            66 => Ok(Protocol::RVD),
            67 => Ok(Protocol::IPPC),
            68 => Ok(Protocol::DISTRIBUTED_FS),
            69 => Ok(Protocol::SAT_MON),
            70 => Ok(Protocol::VISA),
            71 => Ok(Protocol::IPCV),
            72 => Ok(Protocol::CPNX),
            73 => Ok(Protocol::CPHB),
            74 => Ok(Protocol::WSN),
            75 => Ok(Protocol::PVP),
            76 => Ok(Protocol::BR_SAT_MON),
            77 => Ok(Protocol::SUN_ND),
            78 => Ok(Protocol::WB_MON),
            79 => Ok(Protocol::WB_EXPAK),
            80 => Ok(Protocol::ISO_IP),
            81 => Ok(Protocol::VMTP),
            82 => Ok(Protocol::SECURE_VMTP),
            83 => Ok(Protocol::VINES),
            84 => Ok(Protocol::IPTM),
            85 => Ok(Protocol::NSFNET_IGP),
            86 => Ok(Protocol::DGP),
            87 => Ok(Protocol::TCF),
            88 => Ok(Protocol::EIGRP),
            89 => Ok(Protocol::OSPFIGP),
            90 => Ok(Protocol::SpriteRPC),
            91 => Ok(Protocol::LARP),
            92 => Ok(Protocol::MTP),
            93 => Ok(Protocol::AX25),
            94 => Ok(Protocol::IPIP),
            95 => Ok(Protocol::MICP),
            96 => Ok(Protocol::SCC_SP),
            97 => Ok(Protocol::ETHERIP),
            98 => Ok(Protocol::ENCAP),
            99 => Ok(Protocol::PRIVATE_ENCRYPTION),
            100 => Ok(Protocol::GMTP),
            101 => Ok(Protocol::IFMP),
            102 => Ok(Protocol::PNNI),
            103 => Ok(Protocol::PIM),
            104 => Ok(Protocol::ARIS),
            105 => Ok(Protocol::SCPS),
            106 => Ok(Protocol::QNX),
            107 => Ok(Protocol::AN),
            108 => Ok(Protocol::IPComp),
            109 => Ok(Protocol::SNP),
            110 => Ok(Protocol::CompaqPeer),
            111 => Ok(Protocol::IPXinIP),
            112 => Ok(Protocol::VRRP),
            113 => Ok(Protocol::PGM),
            114 => Ok(Protocol::ZERO_HOP),
            115 => Ok(Protocol::L2TP),
            116 => Ok(Protocol::DDX),
            117 => Ok(Protocol::IATP),
            118 => Ok(Protocol::STP),
            119 => Ok(Protocol::SRP),
            120 => Ok(Protocol::UTI),
            121 => Ok(Protocol::SMP),
            122 => Ok(Protocol::SM),
            123 => Ok(Protocol::PTP),
            124 => Ok(Protocol::ISIS_over_IPv4),
            125 => Ok(Protocol::FIRE),
            126 => Ok(Protocol::CRTP),
            127 => Ok(Protocol::CRUDP),
            128 => Ok(Protocol::SSCOPMCE),
            129 => Ok(Protocol::IPLT),
            130 => Ok(Protocol::SPS),
            131 => Ok(Protocol::PIPE),
            132 => Ok(Protocol::SCTP),
            133 => Ok(Protocol::FC),
            134 => Ok(Protocol::RSVP_E2E_IGNORE),
            135 => Ok(Protocol::MobilityHeader),
            136 => Ok(Protocol::UDPLite),
            137 => Ok(Protocol::MPLS_in_IP),
            138 => Ok(Protocol::MANET),
            139 => Ok(Protocol::HIP),
            140 => Ok(Protocol::Shim6),
            141 => Ok(Protocol::WESP),
            142 => Ok(Protocol::ROHC),
            143 => Ok(Protocol::Ethernet),
            144 => Ok(Protocol::AGGFRAG),
            145 => Ok(Protocol::NSH),
            146 => Ok(Protocol::Homa),
            147 => Ok(Protocol::BIT_EMU),
            253 => Ok(Protocol::Experimental253),
            254 => Ok(Protocol::Experimental254),
            255 => Ok(Protocol::Reserved),
            _ => Err(ProtocolError::UnsupportedProtocol),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_try_from_u8() {
        // 正常なケース
        // NOTE: 全プロトコルに対してテストを行なうのは現実的ではないため、代表的なプロトコルのみをテストする
        assert_eq!(Protocol::try_from(1), Ok(Protocol::ICMP));
        assert_eq!(Protocol::try_from(4), Ok(Protocol::IPv4));
        assert_eq!(Protocol::try_from(6), Ok(Protocol::TCP));
        assert_eq!(Protocol::try_from(17), Ok(Protocol::UDP));
        assert_eq!(Protocol::try_from(41), Ok(Protocol::IPv6));
        assert_eq!(Protocol::try_from(255), Ok(Protocol::Reserved));

        // エラーケース（未定義のプロトコル番号）
        let result = Protocol::try_from(200);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ProtocolError::UnsupportedProtocol);
    }

    #[test]
    fn test_protocol_from_u8() {
        // Protocol -> u8 の変換をテスト
        // NOTE: 代表的なプロトコルのみをテストする
        assert_eq!(u8::from(Protocol::ICMP), 1);
        assert_eq!(u8::from(Protocol::IPv4), 4);
        assert_eq!(u8::from(Protocol::TCP), 6);
        assert_eq!(u8::from(Protocol::UDP), 17);
        assert_eq!(u8::from(Protocol::IPv6), 41);
        assert_eq!(u8::from(Protocol::Reserved), 255);
    }
}
