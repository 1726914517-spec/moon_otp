///|
/// One-time recovery (backup) codes.
///
/// Recovery codes are issued alongside TOTP enrollment so users can regain
/// access when their authenticator device is unavailable. Each code is used
/// at most once.

// Unambiguous alphabet: no I/L/O/0/1 to avoid confusion (30 symbols).
let recovery_alphabet : FixedArray[Byte] = [
  b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'J', b'K', b'M', b'N', b'P', b'Q',
  b'R', b'S', b'T', b'V', b'W', b'X', b'Y', b'Z', b'2', b'3', b'4', b'5', b'6', b'7',
  b'8', b'9',
]

///|
fn random_recovery_code(
  groups : Int,
  group_size : Int,
) -> String raise OtpError {
  let total = groups * group_size
  let random = match @env.rand(total) {
    Some(bytes) if bytes.length() == total => bytes
    _ => raise RandomUnavailable
  }
  let out = Buffer()
  for g in 0..<groups {
    if g > 0 {
      out.write_byte(b'-')
    }
    for i in 0..<group_size {
      let idx = random[g * group_size + i].to_int() % 30
      out.write_byte(recovery_alphabet[idx])
    }
  }
  @utf8.decode_lossy(out.to_bytes())
}

///|
/// Generate `count` unique recovery codes, each split into `groups` groups of
/// `group_size` characters (default 10 codes of the form `XXXX-XXXX`).
pub fn generate_recovery_codes(
  count? : Int = 10,
  groups? : Int = 2,
  group_size? : Int = 4,
) -> Array[String] raise OtpError {
  if count < 1 || groups < 1 || group_size < 1 {
    raise InvalidUri("count, groups and group_size must be positive")
  }
  let codes = []
  let mut made = 0
  while made < count {
    let code = random_recovery_code(groups, group_size)
    if !codes.contains(code) {
      codes.push(code)
      made += 1
    }
  }
  codes
}
