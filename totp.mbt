/// TOTP: time-based one-time password, RFC 6238.

///|
/// Compute a TOTP code from a Unix timestamp in seconds.
///
/// - `unix_time`: number of seconds since 1970-01-01.
/// - `digits`: output digits (RFC 6238 uses 6 or 8).
/// - `period`: time step in seconds (default 30).
pub fn totp(
  algorithm : HashAlgorithm,
  key : Bytes,
  unix_time : UInt64,
  digits? : Int = 6,
  period? : Int = 30,
) -> String raise OtpError {
  if period <= 0 {
    raise InvalidPeriod(period)
  }
  let counter = unix_time / period.to_uint64()
  hotp(algorithm, key, counter, digits~)
}

///|
/// Compute the TOTP code for the current system time.
pub fn totp_now(
  algorithm : HashAlgorithm,
  key : Bytes,
  digits? : Int = 6,
  period? : Int = 30,
) -> String raise OtpError {
  // @env.now() returns milliseconds.
  let unix_time = @env.now() / 1000UL
  totp(algorithm, key, unix_time, digits~, period~)
}
