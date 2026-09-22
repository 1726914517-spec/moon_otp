///|
/// Errors returned by the OTP routines.
pub(all) suberror OtpError {
  /// Requested digit count is outside the supported range (1..10).
  InvalidDigits(Int)
  /// The time step must be greater than zero.
  InvalidPeriod(Int)
  /// The shared secret must contain at least one byte.
  EmptySecret
  /// The platform secure random source is unavailable.
  RandomUnavailable
  /// The requested random length is not positive.
  InvalidSecretLength(Int)
  /// The otpauth URI is malformed; carries a human-readable reason.
  InvalidUri(String)
} derive(@debug.Debug)
