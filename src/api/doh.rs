//! DNS over HTTPS (RFC 8484), just enough for alternative routing (T6.3): TXT and A queries in DNS wire
//! format, sent to every provider of [`PROVIDERS`] at once; the first answer wins.

use std::net::Ipv4Addr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// win-app's `DefaultDohProvidersFactory`.
pub const PROVIDERS: [&str; 2] = ["https://dns11.quad9.net/dns-query", "https://dns.google/dns-query"];
/// win-app's `DohClientTimeout`.
const TIMEOUT: Duration = Duration::from_secs(10);

pub const TYPE_A: u16 = 1;
pub const TYPE_TXT: u16 = 16;

#[derive(Debug, thiserror::Error)]
pub enum DohError {
    #[error("DNS over HTTPS: {0}")]
    Http(#[from] reqwest::Error),
    #[error("DNS over HTTPS: HTTP {0}")]
    Status(u16),
    #[error("DNS over HTTPS: malformed answer")]
    Malformed,
    #[error("DNS over HTTPS: no {0} records")]
    NoRecords(&'static str),
    #[error("DNS over HTTPS: bad name {0:?}")]
    BadName(String),
}

/// The TXT records of `name` (each record's strings joined), via the first provider that answers.
pub async fn txt(name: &str) -> Result<Vec<String>, DohError> {
    let answers = query(name, TYPE_TXT).await?;
    let records: Vec<String> = answers.iter().filter_map(|a| a.txt()).collect();
    if records.is_empty() { Err(DohError::NoRecords("TXT")) } else { Ok(records) }
}

/// The IPv4 addresses of `name`.
pub async fn a(name: &str) -> Result<Vec<Ipv4Addr>, DohError> {
    let answers = query(name, TYPE_A).await?;
    let addresses: Vec<Ipv4Addr> = answers.iter().filter_map(Answer::a).collect();
    if addresses.is_empty() { Err(DohError::NoRecords("A")) } else { Ok(addresses) }
}

async fn query(name: &str, record_type: u16) -> Result<Vec<Answer>, DohError> {
    let message = URL_SAFE_NO_PAD.encode(encode_query(name, record_type)?);
    let http = reqwest::Client::builder().timeout(TIMEOUT).build()?;
    let attempts = PROVIDERS.iter().map(|provider| {
        // base64url needs no escaping in a query string.
        let request = http.get(format!("{provider}?dns={message}")).header("Accept", "application/dns-message");
        Box::pin(async move {
            let response = request.send().await?;
            if !response.status().is_success() {
                return Err(DohError::Status(response.status().as_u16()));
            }
            let body: Vec<u8> = response.bytes().await?.to_vec();
            let answers = parse_response(&body).ok_or(DohError::Malformed)?;
            let wanted = answers.iter().any(|a| a.record_type == record_type);
            if wanted { Ok(answers) } else { Err(DohError::NoRecords(if record_type == TYPE_A { "A" } else { "TXT" })) }
        })
    });
    match futures::future::select_ok(attempts).await {
        Ok((answers, _)) => Ok(answers),
        Err(e) => Err(e),
    }
}

/// One resource record of the answer section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub record_type: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl Answer {
    /// A TXT record's character-strings, joined.
    pub fn txt(&self) -> Option<String> {
        if self.record_type != TYPE_TXT {
            return None;
        }
        let mut text = Vec::new();
        let mut rest = self.data.as_slice();
        while let Some((&len, tail)) = rest.split_first() {
            let chunk = tail.get(..len as usize)?;
            text.extend_from_slice(chunk);
            rest = &tail[len as usize..];
        }
        String::from_utf8(text).ok()
    }

    pub fn a(&self) -> Option<Ipv4Addr> {
        if self.record_type != TYPE_A {
            return None;
        }
        let octets: [u8; 4] = self.data.as_slice().try_into().ok()?;
        Some(Ipv4Addr::from(octets))
    }
}

/// A recursion-desired query for `name` (ID 0, as RFC 8484 recommends for caching).
pub fn encode_query(name: &str, record_type: u16) -> Result<Vec<u8>, DohError> {
    let mut message = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(DohError::BadName(name.to_owned()));
        }
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&record_type.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    Ok(message)
}

/// The answer section of a response; `None` when it's malformed or reports an error (RCODE ≠ 0).
pub fn parse_response(message: &[u8]) -> Option<Vec<Answer>> {
    let u16_at = |at: usize| Some(u16::from_be_bytes(message.get(at..at + 2)?.try_into().ok()?));
    if message.len() < 12 || message[3] & 0x0f != 0 {
        return None;
    }
    let questions = u16_at(4)?;
    let answers = u16_at(6)?;
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(message, at)? + 4;
    }
    let mut records = Vec::with_capacity(answers as usize);
    for _ in 0..answers {
        at = skip_name(message, at)?;
        let record_type = u16_at(at)?;
        let ttl = u32::from_be_bytes(message.get(at + 4..at + 8)?.try_into().ok()?);
        let length = u16_at(at + 8)? as usize;
        let data = message.get(at + 10..at + 10 + length)?.to_vec();
        at += 10 + length;
        records.push(Answer { record_type, ttl, data });
    }
    Some(records)
}

/// The offset after the (possibly compressed) name at `at`.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *message.get(at)?;
        match len {
            0 => return Some(at + 1),
            // A compression pointer ends the name.
            l if l & 0xc0 == 0xc0 => return Some(at + 2),
            l => at += 1 + l as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_a_query() {
        let query = encode_query("example.com", TYPE_TXT).unwrap();
        assert_eq!(&query[..12], &[0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x10\x00\x01");
        assert!(encode_query("a..b", TYPE_A).is_err());
    }

    #[test]
    fn parses_cname_then_txt_and_a() {
        // What the resolvers answer for vpn-api.proton.me's route name: a CNAME, then TXT records holding IPs.
        let mut message = vec![0, 0, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        message.extend_from_slice(&encode_query("d.example", TYPE_TXT).unwrap()[12..]);
        // CNAME, name compressed to the question (offset 12).
        message.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 120, 0, 6]);
        message.extend_from_slice(b"\x03vpn\xc0\x0e");
        // TXT "52.59.250.216", owner name compressed.
        message.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 120, 0, 14, 13]);
        message.extend_from_slice(b"52.59.250.216");
        // A record.
        message.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 18, 157, 167, 43]);

        let answers = parse_response(&message).unwrap();
        assert_eq!(answers.len(), 3);
        assert_eq!(answers[1].txt().as_deref(), Some("52.59.250.216"));
        assert_eq!(answers[1].ttl, 120);
        assert_eq!(answers[2].a(), Some(Ipv4Addr::new(18, 157, 167, 43)));
        assert_eq!(answers[0].txt(), None);

        // Truncated, or an error RCODE (NXDOMAIN).
        assert!(parse_response(&message[..message.len() - 2]).is_none());
        let mut nxdomain = message.clone();
        nxdomain[3] = 0x83;
        assert!(parse_response(&nxdomain).is_none());
    }

    #[test]
    fn joins_txt_strings() {
        let answer = Answer { record_type: TYPE_TXT, ttl: 1, data: b"\x03abc\x02de".to_vec() };
        assert_eq!(answer.txt().as_deref(), Some("abcde"));
        let bad = Answer { record_type: TYPE_TXT, ttl: 1, data: b"\x09abc".to_vec() };
        assert_eq!(bad.txt(), None);
    }
}
