// SHA-512 (FIPS 180-4). Used for TOTP with algorithm "SHA512" and any
// HMAC-based construction. Operates on 128-byte blocks with 64-bit words.

///|
let sha512_h : FixedArray[UInt64] = [
  0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
  0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
]

///|
let sha512_k : FixedArray[UInt64] = [
  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
]

///|
fn rotr_u64(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
/// Compute the SHA-512 digest of `data`, returning 64 raw bytes.
pub fn sha512(data : BytesView) -> Bytes {
  // Padding: 0x80, zeros until length ≡ 112 (mod 128), then a 128-bit
  // big-endian bit length.
  let padded = Buffer()
  padded.write_bytesview(data)
  padded.write_byte(0x80)
  while padded.length() % 128 != 112 {
    padded.write_byte(0)
  }
  let bit_length = (data.length() * 8).to_uint64()
  padded.write_uint64_be(0UL) // high 64 bits
  padded.write_uint64_be(bit_length) // low 64 bits
  let msg = padded.to_bytes()

  let h : FixedArray[UInt64] = [
    sha512_h[0],
    sha512_h[1],
    sha512_h[2],
    sha512_h[3],
    sha512_h[4],
    sha512_h[5],
    sha512_h[6],
    sha512_h[7],
  ]

  let words = FixedArray::make(80, 0UL)
  let block_count = msg.length() / 128
  for block in 0..<block_count {
    let base = block * 128
    for t in 0..<16 {
      let off = base + t * 8
      words[t] = (msg[off].to_uint64() << 56) |
        (msg[off + 1].to_uint64() << 48) |
        (msg[off + 2].to_uint64() << 40) |
        (msg[off + 3].to_uint64() << 32) |
        (msg[off + 4].to_uint64() << 24) |
        (msg[off + 5].to_uint64() << 16) |
        (msg[off + 6].to_uint64() << 8) |
        msg[off + 7].to_uint64()
    }
    for t in 16..<80 {
      let w15 = words[t - 15]
      let w2 = words[t - 2]
      let s0 = rotr_u64(w15, 1).lxor(rotr_u64(w15, 8)).lxor(w15 >> 7)
      let s1 = rotr_u64(w2, 19).lxor(rotr_u64(w2, 61)).lxor(w2 >> 6)
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
    for t in 0..<80 {
      let s1 = rotr_u64(e, 14).lxor(rotr_u64(e, 18)).lxor(rotr_u64(e, 41))
      let ch = (e & f) ^ (e.lnot() & g)
      let t1 = hh + s1 + ch + sha512_k[t] + words[t]
      let s0 = rotr_u64(a, 28).lxor(rotr_u64(a, 34)).lxor(rotr_u64(a, 39))
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
    out.write_uint64_be(h[i])
  }
  out.to_bytes()
}
