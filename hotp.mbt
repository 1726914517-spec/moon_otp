///|
/// HOTP: HMAC-based one-time password, RFC 4226.
fn zero_pad(code : Int, digits : Int) -> String {
  let s = code.to_string()
  let b = Buffer()
  for _ in 0..<(digits - s.length()) {
    b.write_byte(0x30)
  }
  b.write_string_utf8(s)
  @utf8.decode_lossy(b.to_bytes())
}

///|
/// Compute an HOTP code.
///
/// - `algorithm`: hash function used for the HMAC.
/// - `key`: shared secret (RFC test keys are ASCII; real deployments use random bytes).
/// - `counter`: 8-byte moving factor.
/// - `digits`: number of output digits (RFC 4226 recommends 6; supported 1..8).
pub fn hotp(
  algorithm : HashAlgorithm,
  key : Bytes,
  counter : UInt64,
  digits? : Int = 6,
) -> String raise OtpError {
  if digits < 1 || digits > 8 {
    raise InvalidDigits(digits)
  }
  if key.length() == 0 {
    raise EmptySecret
  }
  let counter_buf = Buffer()
  counter_buf.write_uint64_be(counter)
  let mac = hmac(algorithm, key, counter_buf.to_bytes())
  // Dynamic truncation (RFC 4226 §5.3).
  let offset = (mac[mac.length() - 1] & 0x0f).to_int()
  let bin_code = ((mac[offset] & 0x7f).to_uint() << 24) |
    (mac[offset + 1].to_uint() << 16) |
    (mac[offset + 2].to_uint() << 8) |
    mac[offset + 3].to_uint()
  let mut modulus = 1
  for _ in 0..<digits {
    modulus *= 10
  }
  let code = (bin_code % modulus.reinterpret_as_uint()).reinterpret_as_int()
  zero_pad(code, digits)
}

///|
/// Resynchronize an HOTP client counter per RFC 4226 §7.4.
///
/// The client submits two consecutive codes; the server searches a look-ahead
/// `window` starting from its stored counter. Returns the counter matching
/// the first code, or `None` if the pair was not found.
pub fn hotp_resync(
  algorithm : HashAlgorithm,
  key : Bytes,
  current_counter : UInt64,
  code1 : String,
  code2 : String,
  window? : Int = 5,
) -> UInt64? raise OtpError {
  if window < 0 {
    raise InvalidUri("window must be non-negative")
  }
  let mut i = 0
  while i <= window {
    let counter = current_counter + i.to_uint64()
    if hotp(algorithm, key, counter) == code1 &&
      hotp(algorithm, key, counter + 1UL) == code2 {
      return Some(counter)
    }
    i += 1
  }
  None
}
