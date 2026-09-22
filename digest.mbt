// Unified hash algorithm selection used by HMAC and the OTP APIs.

///|
/// Cryptographic hash algorithms supported by this package.
pub(all) enum HashAlgorithm {
  /// SHA-1: 20-byte digest, 64-byte block. The OTP default.
  Sha1
  /// SHA-256: 32-byte digest64-byte block.
  Sha256
  /// SHA-512: 64-byte digest, 128-byte block.
  Sha512
} derive(Debug, Eq)

///|
/// Block size in bytes of the algorithm's compression function.
pub fn block_size(algo : HashAlgorithm) -> Int {
  match algo {
    Sha1 => 64
    Sha256 => 64
    Sha512 => 128
  }
}

///|
/// Output digest length in bytes.
pub fn output_size(algo : HashAlgorithm) -> Int {
  match algo {
    Sha1 => 20
    Sha256 => 32
    Sha512 => 64
  }
}

///|
/// One-shot hash: compute the digest of all of `data`.
pub fn digest(algo : HashAlgorithm, data : BytesView) -> Bytes {
  match algo {
    Sha1 => sha1(data)
    Sha256 => sha256(data)
    Sha512 => sha512(data)
  }
}

///|
/// Canonical name used in otpauth:// URIs ("SHA1", "SHA256", "SHA512").
pub fn algorithm_name(algo : HashAlgorithm) -> String {
  match algo {
    Sha1 => "SHA1"
    Sha256 => "SHA256"
    Sha512 => "SHA512"
  }
}

///|
/// Parse an algorithm name as it appears in otpauth URIs. Case insensitive.
/// Unknown names return `None`.
pub fn parse_algorithm(name : String) -> HashAlgorithm? {
  match name.to_upper() {
    "SHA1" => Some(Sha1)
    "SHA256" => Some(Sha256)
    "SHA512" => Some(Sha512)
    _ => None
  }
}
