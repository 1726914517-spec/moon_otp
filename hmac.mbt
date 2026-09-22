// HMAC (RFC 2104), parameterized over any supported hash algorithm.

///|
/// Compute HMAC: `H((K' xor opad) || H((K' xor ipad) || message))`.
///
/// Keys longer than the hash block size are first replaced by their digest.
/// Shorter keys are zero-padded to the block size.
pub fn hmac(
  algo : HashAlgorithm,
  key : BytesView,
  message : BytesView,
) -> Bytes {
  let bs = block_size(algo)

  // Normalize the key to at most one block.
  let norm = if key.length() > bs {
    digest(algo, key)
  } else {
    let b = Buffer()
    b.write_bytesview(key)
    b.to_bytes()
  }

  // Inner pass: (K xor ipad) || message.
  let inner_input = Buffer()
  for i in 0..<bs {
    let kb = if i < norm.length() { norm[i] } else { b'\x00' }
    inner_input.write_byte(kb ^ 0x36)
  }
  inner_input.write_bytesview(message)
  let inner = digest(algo, inner_input.to_bytes())

  // Outer pass: (K xor opad) || inner digest.
  let outer_input = Buffer()
  for i in 0..<bs {
    let kb = if i < norm.length() { norm[i] } else { b'\x00' }
    outer_input.write_byte(kb ^ 0x5c)
  }
  outer_input.write_bytesview(inner)
  digest(algo, outer_input.to_bytes())
}
