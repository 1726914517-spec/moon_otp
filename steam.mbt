///|
/// Steam Guard mobile authenticator codes.
///
/// Steam uses a TOTP-like construction (RFC 6238 timing, HMAC-SHA-1, dynamic
/// truncation) but emits five characters drawn from a 26-symbol custom
/// alphabet instead of decimal digits.
let steam_alphabet : FixedArray[Byte] = [
  b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'B', b'C', b'D', b'F', b'G', b'H',
  b'J', b'K', b'M', b'N', b'P', b'Q', b'R', b'T', b'V', b'W', b'X', b'Y',
]

///|
/// Compute a Steam Guard code from a Unix timestamp in seconds.
pub fn steam_guard(
  key : Bytes,
  unix_time : UInt64,
  period? : Int = 30,
) -> String raise OtpError {
  if key.length() == 0 {
    raise EmptySecret
  }
  if period <= 0 {
    raise InvalidPeriod(period)
  }
  let counter = unix_time / period.to_uint64()
  let counter_buf = Buffer()
  counter_buf.write_uint64_be(counter)
  let mac = hmac(Sha1, key, counter_buf.to_bytes())
  // Same dynamic truncation as HOTP (RFC 4226 §5.3).
  let offset = (mac[mac.length() - 1] & 0x0f).to_int()
  let mut bin_code = ((mac[offset] & 0x7f).to_uint() << 24) |
    (mac[offset + 1].to_uint() << 16) |
    (mac[offset + 2].to_uint() << 8) |
    mac[offset + 3].to_uint()
  let out = Buffer()
  for _ in 0..<5 {
    out.write_byte(steam_alphabet[(bin_code % 26U).to_int()])
    bin_code /= 26U
  }
  @utf8.decode_lossy(out.to_bytes())
}

///|
/// Compute the Steam Guard code for the current system time.
pub fn steam_guard_now(key : Bytes) -> String raise OtpError {
  // @env.now() returns milliseconds.
  steam_guard(key, @env.now() / 1000UL)
}
