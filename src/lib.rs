use h3::ext::Protocol;
use std::net::{SocketAddr, ToSocketAddrs};

pub mod client;
pub mod server;

/**
 * RFC9298 specify connect-udp path should be a template like /.well-known/masque/udp/192.0.2.6/443/
 */
pub(crate) fn socketaddr_to_connect_udp_path(addr: &Option<SocketAddr>) -> String {
    if let Some(addr) = addr {
        let ip_string = addr.ip().to_string().replace(":", "%3A"); // encode ':' in IPv6 address in URI
        format!("/.well_known/masque/udp/{}/{}/", ip_string, addr.port())
    } else {
        "/.well_known/masque/udp/%2A/%2A/".to_string()
    }
}

/**
 * Parse pseudo-header path for CONNECT UDP to SocketAddr
 */
pub(crate) fn path_to_socketaddr(path: &[u8]) -> Option<SocketAddr> {
    // for now, let's assume path pattern is "/something.../target-host/target-port/"
    let mut split_iter = std::io::BufRead::split(path, b'/');
    let mut second_last = None;
    let mut last = None;
    while let Some(curr) = split_iter.next() {
        if let Ok(curr) = curr {
            second_last = last;
            last = Some(curr);
        } else {
            return None;
        }
    }
    if second_last.is_some() && last.is_some() {
        let second_last = second_last.unwrap();
        let last = last.unwrap();
        let second_last = std::str::from_utf8(&second_last);
        let last = std::str::from_utf8(&last);
        if second_last.is_ok() && last.is_ok() {
            let url_str = format!("scheme://{}:{}/", second_last.unwrap(), last.unwrap());
            let url = url::Url::parse(&url_str);
            if let Ok(url) = url {
                let socket_addrs = url.to_socket_addrs();
                if let Ok(mut socket_addrs) = socket_addrs {
                    return socket_addrs.next();
                }
            }
        }
    }

    None
}

pub(crate) fn decode_var_int(data: &[u8]) -> Option<(u64, &[u8])> {
    // The length of variable-length integers is encoded in the
    // first two bits of the first byte.
    let mut v: u64 = data[0].into();
    let prefix = v >> 6;
    let length = 1 << prefix;

    if data.len() < length {
        return None;
    }
    // Once the length is known, remove these bits and read any
    // remaining bytes.
    v = v & 0x3f;
    for i in 1..length - 1 {
        v = (v << 8) + Into::<u64>::into(data[i]);
    }

    Some((v, &data[length..]))
}

pub(crate) fn encode_var_int(mut v: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let length = if v < 0x40 {
        1
    } else if v < 0x4000 {
        2
    } else if v < 0x400000 {
        4
    } else {
        8
    };
    let prefix = match length {
        1 => 0b00,
        2 => 0b01,
        4 => 0b10,
        8 => 0b11,
        _ => unreachable!(),
    };
    let mut first_byte = (prefix << 6) as u8;
    for _ in (1..length).rev() {
        let byte = (v & 0xff) as u8;
        buf.insert(0, byte);
        v >>= 8;
    }
    first_byte |= (v & 0x3f) as u8;
    buf.insert(0, first_byte);
    buf
}

pub(crate) fn validate_connect_udp(request: &http::request::Request<()>) -> bool {
    let protocol = request.extensions().get::<Protocol>();
    matches!((request.method(), protocol), (&http::Method::CONNECT, Some(p)) if p == &Protocol::CONNECT_UDP)
}
