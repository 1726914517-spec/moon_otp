// Tests for SHA-1/SHA-256/SHA-512 against the FIPS 180-4 / NIST sample vectors
// and for HMAC against RFC 2202.

///|
fn hex_digit(c : Char) -> Int {
  match c {
    '0'..='9' => c.to_int() - '0'.to_int()
    'a'..='f' => c.to_int() - 'a'.to_int() + 10
    'A'..='F' => c.to_int() - 'A'.to_int() + 10
    _ => abort("bad hex digit")
  }
}

///|
fn from_hex(s : String) -> Bytes {
  let b = Buffer()
  for i in 0..<(s.length() / 2) {
    let hi = hex_digit(s.get_char(i * 2).unwrap())
    let lo = hex_digit(s.get_char(i * 2 + 1).unwrap())
    b.write_byte(((hi * 16 + lo) & 0xff).to_byte())
  }
  b.to_bytes()
}

///|
test "sha1 empty and abc" {
  @test.assert_eq(
    from_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    sha1(@utf8.encode("")),
  )
  @test.assert_eq(
    from_hex("a9993e364706816aba3e25717850c26c9cd0d89d"),
    sha1(@utf8.encode("abc")),
  )
}

///|
test "sha1 long two-block message" {
  @test.assert_eq(
    from_hex("84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
    sha1(
      @utf8.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ),
  )
}

///|
test "sha256 empty and abc" {
  @test.assert_eq(
    from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    sha256(@utf8.encode("")),
  )
  @test.assert_eq(
    from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    sha256(@utf8.encode("abc")),
  )
}

///|
test "sha256 long two-block message" {
  @test.assert_eq(
    from_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    sha256(
      @utf8.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ),
  )
}

///|
test "sha512 empty and abc" {
  @test.assert_eq(
    from_hex(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ),
    sha512(@utf8.encode("")),
  )
  @test.assert_eq(
    from_hex(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    sha512(@utf8.encode("abc")),
  )
}

///|
test "sha512 long two-block message" {
  @test.assert_eq(
    from_hex(
      "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
    ),
    sha512(
      @utf8.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ),
  )
}

///|
test "unified digest dispatch" {
  @test.assert_eq(20, digest(Sha1, @utf8.encode("abc")).length())
  @test.assert_eq(32, digest(Sha256, @utf8.encode("abc")).length())
  @test.assert_eq(64, digest(Sha512, @utf8.encode("abc")).length())
}

///|
test "hmac sha1 rfc2202 hi there" {
  let key = Bytes::make(20, b'\x0b')
  @test.assert_eq(
    from_hex("b617318655057264e28bc0b6fb378c8ef146be00"),
    hmac(Sha1, key, @utf8.encode("Hi There")),
  )
}

///|
test "hmac sha256 rfc4231 case 1" {
  let key = Bytes::make(20, b'\x0b')
  @test.assert_eq(
    from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    hmac(Sha256, key, @utf8.encode("Hi There")),
  )
}

///|
test "hmac sha512 rfc4231 case 1" {
  let key = Bytes::make(20, b'\x0b')
  @test.assert_eq(
    from_hex(
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    ),
    hmac(Sha512, key, @utf8.encode("Hi There")),
  )
}

///|
test "hmac sha256/512 rfc4231 case 2 jefe" {
  let key = @utf8.encode("Jefe")
  let data = @utf8.encode("what do ya want for nothing?")
  @test.assert_eq(
    from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    hmac(Sha256, key, data),
  )
  @test.assert_eq(
    from_hex(
      "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    ),
    hmac(Sha512, key, data),
  )
}
