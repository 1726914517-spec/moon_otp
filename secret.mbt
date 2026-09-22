/// Random shared-secret generation.

///|
/// Generate `length` cryptographically random secret bytes.
pub fn generate_secret(length? : Int = 20) -> Bytes raise OtpError {
  if length < 1 {
    raise InvalidSecretLength(length)
  }
  match @env.rand(length) {
    Some(bytes) if bytes.length() == length => bytes
    _ => raise RandomUnavailable
  }
}

///|
/// Generate a secret and return it as an unpadded RFC 4648 Base32 string,
/// the format used by Google Authenticator / most 2FA enrollment flows.
pub fn generate_secret_base32(length? : Int = 20) -> String raise OtpError {
  let bytes = generate_secret(length~)
  base32_encode_unpadded(bytes)
}
