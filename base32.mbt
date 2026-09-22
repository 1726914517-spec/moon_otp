// RFC 4648 Base32 encoding/decoding.
// Two alphabets are supported:
//   - standard: A-Z2-7
//   - extended hex: 0-9A-V
// OTP secret keys in otpauth:// URIs use the standard alphabet without
// padding in practice, while RFC 4648 mandates "=" padding. The decoder
// accepts both forms and validates padding when it is present.

///|
/// Error returned when Base32 decoding fails.
pub(all) suberror Base32Error {
  /// Character at the given position is not part of the alphabet or padding.
  InvalidCharacter(Int, Char)
  /// Padding ("=") appears in an illegal place or with the wrong length.
  InvalidPadding(Int)
} derive(@debug.Debug)

///|
priv enum Alphabet {
  Standard
  Hex
}

///|
const STANDARD_TABLE : String = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

///|
const HEX_TABLE : String = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

///|
fn alphabet_char(alpha : Alphabet, index : UInt) -> Char {
  let i = index.reinterpret_as_int()
  match alpha {
    Standard => STANDARD_TABLE.get_char(i).unwrap()
    Hex => HEX_TABLE.get_char(i).unwrap()
  }
}

///|
fn decode_char(alpha : Alphabet, c : Char) -> Int? {
  match alpha {
    Standard =>
      match c {
        'A'..='Z' => Some(c.to_int() - 'A'.to_int())
        '2'..='7' => Some(c.to_int() - '2'.to_int() + 26)
        _ => None
      }
    Hex =>
      match c {
        '0'..='9' => Some(c.to_int() - '0'.to_int())
        'A'..='V' => Some(c.to_int() - 'A'.to_int() + 10)
        _ => None
      }
  }
}

///|
fn encode_with(data : BytesView, alpha : Alphabet, padding~ : Bool) -> String {
  let out = Buffer()
  let mut acc : UInt = 0
  let mut bits = 0
  for i in 0..<data.length() {
    acc = (acc << 8) | data[i].to_uint()
    bits += 8
    while bits >= 5 {
      let index = (acc >> (bits - 5)) & 0x1FU
      out.write_char_utf8(alphabet_char(alpha, index))
      bits -= 5
    }
  }
  if bits > 0 {
    let index = (acc << (5 - bits)) & 0x1FU
    out.write_char_utf8(alphabet_char(alpha, index))
  }
  if padding {
    while out.length() % 8 != 0 {
      out.write_char_utf8('=')
    }
  }
  // The buffer holds UTF-8 bytes written by write_char_utf8; decode them back
  // to a String. Every written char is valid UTF-8, so lossy decoding cannot
  // replace anything.
  @utf8.decode_lossy(out.to_bytes())
}

///|
/// Encode bytes with the standard Base32 alphabet, including "=" padding.
pub fn base32_encode(data : BytesView) -> String {
  encode_with(data, Standard, padding=true)
}

///|
/// Encode bytes with the standard Base32 alphabet, omitting padding.
/// This is the form used by Google Authenticator / otpauth secret keys.
pub fn base32_encode_unpadded(data : BytesView) -> String {
  encode_with(data, Standard, padding=false)
}

///|
/// Encode bytes with the Base32 Extended Hex alphabet (RFC 4648 section 7).
pub fn base32_hex_encode(data : BytesView) -> String {
  encode_with(data, Hex, padding=true)
}

///|
fn decode_with(input : String, alpha : Alphabet) -> Bytes raise Base32Error {
  let out = Buffer()
  let mut acc : UInt = 0
  let mut bits = 0
  let mut seen_padding = false
  let mut pad_count = 0
  let mut data_chars = 0
  for i in 0..<input.length() {
    let c = input.get_char(i).unwrap()
    if c == '=' {
      seen_padding = true
      pad_count += 1
      continue
    }
    if seen_padding {
      raise InvalidPadding(i)
    }
    match decode_char(alpha, c) {
      Some(v) => {
        acc = (acc << 5) | v.reinterpret_as_uint()
        bits += 5
        data_chars += 1
        if bits >= 8 {
          let b = ((acc >> (bits - 8)) & 0xFFU).to_byte()
          out.write_byte(b)
          bits -= 8
        }
      }
      None => raise InvalidCharacter(i, c)
    }
  }
  // Validate padding: total encoded length must be a multiple of 8, and the
  // number of "=" must agree with the number of data characters.
  if pad_count != 0 {
    let total = data_chars + pad_count
    if total % 8 != 0 {
      raise InvalidPadding(input.length() - 1)
    }
    // Expected padding per data-character count modulo 8:
    // 0->0, 2->6, 4->4, 5->3, 7->1
    let expected = match data_chars % 8 {
      0 => 0
      2 => 6
      4 => 4
      5 => 3
      7 => 1
      _ => raise InvalidPadding(input.length() - 1)
    }
    if pad_count != expected {
      raise InvalidPadding(input.length() - 1)
    }
  } else {
    let rem = data_chars % 8
    // An unpadded string with an impossible number of data characters.
    if rem == 1 || rem == 3 || rem == 6 {
      raise InvalidPadding(input.length())
    }
  }
  // Leftover 0..4 bits must all be zero, otherwise the string carried extra
  // trailing bits that cannot round-trip.
  if bits > 0 && (acc & ((1U << bits) - 1U)) != 0 {
    raise InvalidPadding(input.length())
  }
  out.to_bytes()
}

///|
/// Decode a standard Base32 string. Padding is optional but validated when
/// present. Whitespace is not accepted; strip it beforehand if needed.
pub fn base32_decode(input : String) -> Bytes raise Base32Error {
  decode_with(input, Standard)
}

///|
/// Decode a Base32 Extended Hex string (RFC 4648 section 7).
pub fn base32_hex_decode(input : String) -> Bytes raise Base32Error {
  decode_with(input, Hex)
}
