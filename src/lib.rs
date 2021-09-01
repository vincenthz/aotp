//! OTP (One time password) supports through HOTP (Hash-based) and TOTP (Time-based)
//!
//! HOTP is described at [RFC4226](https://tools.ietf.org/html/rfc4226)
//! TOTP is described at [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)
//!
//! ```
//! use aotp::{OTP, otp};
//!
//! ```

use cryptoxide::hmac::Hmac;
use cryptoxide::mac::Mac;
use cryptoxide::sha1::Sha1;
use cryptoxide::sha2::{Sha256, Sha512};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

/// Algorithm for running HMAC
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Period of time
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Period(u32);

impl Period {
    pub const fn seconds30() -> Self {
        Period(30)
    }
    pub const fn seconds45() -> Self {
        Period(45)
    }
    pub const fn seconds60() -> Self {
        Period(60)
    }
}

/// 31 bits authentication token
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token(u32);

impl Token {
    pub fn dec6(self) -> String {
        format!("{:06}", self.0 % 1_000_000)
    }
    pub fn dec7(self) -> String {
        format!("{:07}", self.0 % 10_000_000)
    }
    pub fn dec8(self) -> String {
        format!("{:08}", self.0 % 100_000_000)
    }

    pub fn match_code(self, digits: u32, code: u32) -> bool {
        let expected = self.0 % 10u32.pow(digits);
        expected == code
    }
}

impl From<Period> for u32 {
    fn from(p: Period) -> Self {
        p.0
    }
}

/// Storage of all OTP parameters
///
/// This can be transform to and from URLs, which
/// is commonly used to store in QR code, but also
/// can be used for genericly storing
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OTP {
    pub issuer: String,
    pub account: Option<String>,
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub period: Period,
    pub digits: u32,
}

const SCHEME: &str = "otpauth";
const OTP_ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };

impl OTP {
    pub fn validate_now(&self, code: u32) -> bool {
        otp(
            self.algorithm,
            &self.secret,
            Counter::totp_now(self.period.0),
        )
        .match_code(self.digits, code)
    }

    /// get the TOTP code for now
    pub fn totp_now(&self) -> (Token, Duration) {
        let (ctr, left) = Counter::totp_now_left(self.period.0);
        (otp(self.algorithm, &self.secret, ctr), left)
    }

    /// get the TOTP code for now
    pub fn totp_at(&self, ctr: Counter) -> Token {
        otp(self.algorithm, &self.secret, ctr)
    }

    pub fn from_url(url: &url::Url) -> Result<Self, ()> {
        if url.scheme() != SCHEME {
            return Err(());
        }
        if let Some(host) = url.host() {
            if host.to_string() != "totp" {
                return Err(());
            }
        } else {
            return Err(());
        }

        let path = url.path().strip_prefix("/").ok_or(())?;

        let (issuer, account) = match path.split_once(":") {
            None => (path.to_string(), None),
            Some((issuer, account)) => (issuer.to_string(), Some(account.to_string())),
        };

        let mut secret = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = 6u32;
        let mut period = 30u32;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "secret" => {
                    secret = Some(value.into_owned());
                }
                "algorithm" => match value.as_ref() {
                    "SHA1" => algorithm = Algorithm::Sha1,
                    "SHA256" => algorithm = Algorithm::Sha256,
                    "SHA512" => algorithm = Algorithm::Sha512,
                    _ => return Err(()),
                },
                "digits" => {
                    digits = u32::from_str(value.as_ref()).map_err(|_| ())?;
                }
                "period" => {
                    period = u32::from_str(value.as_ref()).map_err(|_| ())?;
                }
                _ => return Err(()),
            }
        }

        if let Some(secret) = secret {
            let secret = base32::decode(OTP_ALPHABET, &secret).ok_or(())?;
            Ok(OTP {
                issuer,
                account,
                secret,
                algorithm,
                period: Period(period),
                digits,
            })
        } else {
            Err(())
        }
    }

    pub fn to_url(&self) -> url::Url {
        let path = if let Some(acc) = &self.account {
            format!("{}:{}", self.issuer, acc)
        } else {
            format!("{}", self.issuer)
        };
        let mut url = url::Url::parse(&format!("{}://totp/{}", SCHEME, path)).unwrap();

        let secret = base32::encode(OTP_ALPHABET, &self.secret);
        let algorithm = match self.algorithm {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        };
        url.query_pairs_mut()
            .append_pair("secret", &secret)
            .append_pair("algorithm", algorithm)
            .append_pair("period", &format!("{}", self.period.0))
            .append_pair("digits", &format!("{}", self.digits));
        url
    }
}

/// Counter to use for otp
#[derive(Clone, Copy, Debug)]
pub struct Counter(u64);

impl Counter {
    /// The counter is zero
    pub const fn zero() -> Self {
        Counter(0)
    }

    /// Increase the counter to the next value
    pub const fn incr(self) -> Self {
        Counter(self.0 + 1)
    }

    pub const fn hotp(counter: u64) -> Self {
        Counter(counter)
    }

    pub fn totp_now(period: u32) -> Self {
        let secs = SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Counter(secs / (period as u64))
    }

    pub fn totp_now_left(period: u32) -> (Self, Duration) {
        let secs = SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let period = period as u128 * 1000;
        let slot = (secs / period) as u64;
        let left = period - (secs % period);
        let left = Duration::from_millis(left as u64);
        (Counter(slot), left)
    }

    pub fn totp_at(period: u32, at: std::time::SystemTime) -> Self {
        let secs = at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Counter(secs / (period as u64))
    }
}

pub fn otp(algorithm: Algorithm, secret: &[u8], counter: Counter) -> Token {
    let hmac_message = counter.0.to_be_bytes();
    let mut output = [0u8; 64];

    let size = match algorithm {
        Algorithm::Sha1 => {
            let mut hmac = Hmac::new(Sha1::new(), secret);
            hmac.input(&hmac_message);
            hmac.raw_result(&mut output[0..20]);
            20
        }
        Algorithm::Sha256 => {
            let mut hmac = Hmac::new(Sha256::new(), secret);
            hmac.input(&hmac_message);
            hmac.raw_result(&mut output[0..32]);
            32
        }
        Algorithm::Sha512 => {
            let mut hmac = Hmac::new(Sha512::new(), secret);
            hmac.input(&hmac_message);
            hmac.raw_result(&mut output[0..64]);
            64
        }
    };

    // calculate the dynamic offset for the value
    let dynamic_offset = (output[size - 1] & (0xf as u8)) as usize;

    // build the u32 code from the hash
    let tok = ((output[dynamic_offset] as u32) & 0x7f) << 24
        | (output[dynamic_offset + 1] as u32) << 16
        | (output[dynamic_offset + 2] as u32) << 8
        | (output[dynamic_offset + 3] as u32);
    Token(tok)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 20] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];

    const TEST_RESULTS: [u32; 10] = [
        755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
    ];

    #[test]
    fn it_works() {
        let mut counter = Counter::zero();

        for r in &TEST_RESULTS {
            let token = otp(Algorithm::Sha1, &TEST_KEY, counter);
            assert!(token.match_code(6, *r));
            counter = counter.incr();
        }
    }

    #[test]
    fn url_parse() {
        let otp = OTP {
            issuer: "issuer".to_string(),
            account: None,
            secret: vec![1, 2, 3, 4],
            period: Period(30),
            digits: 6,
            algorithm: Algorithm::Sha1,
        };
        assert_eq!(OTP::from_url(&otp.to_url()), Ok(otp));
    }
}
