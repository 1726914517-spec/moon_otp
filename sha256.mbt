// SHA-256 (FIPS 180-4). Used for TOTP with algorithm "SHA256" and available
// for any HMAC-based construction.

///|
let sha256_h : FixedArray[UInt] = [
  0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU,
  0x5be0cd19U,
]

///|
let sha256_k : FixedArray[UInt] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn rotr_u32(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
/// Compute the SHA-256 digest of `data`, returning 32 raw bytes.
pub fn sha256(data : BytesView) -> Bytes {
  let padded = Buffer()
  padded.write_bytesview(data)
  padded.write_byte(0x80)
  while padded.length() % 64 != 56 {
    padded.write_byte(0)
  }
  let bit_length = data.length() * 8
  padded.write_uint_be(0U)
  padded.write_uint_be(bit_length.reinterpret_as_uint())
  let msg = padded.to_bytes()

  let h : FixedArray[UInt] = [
    sha256_h[0],
    sha256_h[1],
    sha256_h[2],
    sha256_h[3],
    sha256_h[4],
    sha256_h[5],
    sha256_h[6],
    sha256_h[7],
  ]

  let words = FixedArray::make(64, 0U)
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
    for t in 16..<64 {
      let w15 = words[t - 15]
      let w2 = words[t - 2]
      let s0 = rotr_u32(w15, 7).lxor(rotr_u32(w15, 18)).lxor(w15 >> 3)
      let s1 = rotr_u32(w2, 17).lxor(rotr_u32(w2, 19)).lxor(w2 >> 10)
      words[t] = words[t - 16] + s0 + words[t - 7] + s1
    }
    let mut a = h[0]
    let mut b = h[1]
    let mut c = h[2]
    let mut d = h[3]
    let mut e = h[4]
    let mut f = h[5]
    let mut g = h[6]
    let mut hh = h[7]
    for t in 0..<64 {
      let s1 = rotr_u32(e, 6).lxor(rotr_u32(e, 11)).lxor(rotr_u32(e, 25))
      let ch = (e & f) ^ (e.lnot() & g)
      let t1 = hh + s1 + ch + sha256_k[t] + words[t]
      let s0 = rotr_u32(a, 2).lxor(rotr_u32(a, 13)).lxor(rotr_u32(a, 22))
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let t2 = s0 + maj
      hh = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2
    }
    h[0] = h[0] + a
    h[1] = h[1] + b
    h[2] = h[2] + c
    h[3] = h[3] + d
    h[4] = h[4] + e
    h[5] = h[5] + f
    h[6] = h[6] + g
    h[7] = h[7] + hh
  }
  let out = Buffer()
  for i in 0..<8 {
    out.write_uint_be(h[i])
  }
  out.to_bytes()
}
