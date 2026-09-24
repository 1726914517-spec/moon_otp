// SHA-1 (FIPS 180-4). Included for RFC 4226/6238 compatibility: HOTP and
// TOTP default to SHA-1. SHA-1 is broken for collision resistance but remains
// the mandatory default for one-time passwords.

///|
const SHA1_H0 : UInt = 0x67452301U

///|
const SHA1_H1 : UInt = 0xEFCDAB89U

///|
const SHA1_H2 : UInt = 0x98BADCFEU

///|
const SHA1_H3 : UInt = 0x10325476U

///|
const SHA1_H4 : UInt = 0xC3D2E1F0U

///|
const SHA1_K1 : UInt = 0x5A827999U

///|
const SHA1_K2 : UInt = 0x6ED9EBA1U

///|
const SHA1_K3 : UInt = 0x8F1BBCDCU

///|
const SHA1_K4 : UInt = 0xCA62C1D6U

///|
fn rotl_u32(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
/// Compute the SHA-1 digest of `data`, returning 20 raw bytes.
pub fn sha1(data : BytesView) -> Bytes {
  // Padded message: data || 0x80 || zero bytes || 64-bit big-endian bit length.
  let padded = Buffer()
  padded.write_bytesview(data)
  padded.write_byte(0x80)
  while padded.length() % 64 != 56 {
    padded.write_byte(0)
  }
  let bit_length = data.length() * 8
  padded.write_uint_be(0U) // high 32 bits (messages fit in low 32 bits)
  padded.write_uint_be(bit_length.reinterpret_as_uint()) // low 32 bits
  let msg = padded.to_bytes()

  let mut h0 = SHA1_H0
  let mut h1 = SHA1_H1
  let mut h2 = SHA1_H2
  let mut h3 = SHA1_H3
  let mut h4 = SHA1_H4

  let words = FixedArray::make(80, 0U)
  let block_count = msg.length() / 64
  for block in 0..<block_count {
    let base = block * 64
    for t in 0..<16 {
      let off = base + t * 4
      words[t] = (msg[off].to_uint() << 24) |
        (msg[off + 1].to_uint() << 16) |
        (msg[off + 2].to_uint() << 8) |
        msg[off + 3].to_uint()
    }
    for t in 16..<80 {
      words[t] = rotl_u32(
        words[t - 3].lxor(words[t - 8]).lxor(words[t - 14]).lxor(words[t - 16]),
        1,
      )
    }
    let mut a = h0
    let mut b = h1
    let mut c = h2
    let mut d = h3
    let mut e = h4
    for t in 0..<80 {
      let (f, k) = if t < 20 {
        ((b & c) | (b.lnot() & d), SHA1_K1)
      } else if t < 40 {
        (b.lxor(c).lxor(d), SHA1_K2)
      } else if t < 60 {
        ((b & c) | (b & d) | (c & d), SHA1_K3)
      } else {
        (b.lxor(c).lxor(d), SHA1_K4)
      }
      let temp = rotl_u32(a, 5) + f + e + k + words[t]
      e = d
      d = c
      c = rotl_u32(b, 30)
      b = a
      a = temp
    }
    h0 = h0 + a
    h1 = h1 + b
    h2 = h2 + c
    h3 = h3 + d
    h4 = h4 + e
  }
  let out = Buffer()
  out.write_uint_be(h0)
  out.write_uint_be(h1)
  out.write_uint_be(h2)
  out.write_uint_be(h3)
  out.write_uint_be(h4)
  out.to_bytes()
}
