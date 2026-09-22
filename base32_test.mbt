// RFC 4648 section 10 test vectors plus round-trip and error cases.

///|
test "RFC 4648 base32 encode vectors" {
  let cases = [
    ("", ""),
    ("f", "MY======"),
    ("fo", "MZXQ===="),
    ("foo", "MZXW6==="),
    ("foob", "MZXW6YQ="),
    ("fooba", "MZXW6YTB"),
    ("foobar", "MZXW6YTBOI======"),
  ]
  for pair in cases {
    let input = pair.0
    let want = pair.1
    @test.assert_eq(base32_encode(@utf8.encode(input)), want)
  }
}

///|
test "RFC 4648 base32 decode vectors" {
  let cases = [
    ("", ""),
    ("MY======", "f"),
    ("MZXQ====", "fo"),
    ("MZXW6===", "foo"),
    ("MZXW6YQ=", "foob"),
    ("MZXW6YTB", "fooba"),
    ("MZXW6YTBOI======", "foobar"),
  ]
  for pair in cases {
    let input = pair.0
    let want = pair.1
    @test.assert_eq(@utf8.decode(base32_decode(input)), want)
  }
}

///|
test "RFC 4648 base32 extended-hex vectors" {
  let cases = [
    ("", ""),
    ("f", "CO======"),
    ("fo", "CPNG===="),
    ("foo", "CPNMU==="),
    ("foob", "CPNMUOG="),
    ("fooba", "CPNMUOJ1"),
    ("foobar", "CPNMUOJ1E8======"),
  ]
  for pair in cases {
    let input = pair.0
    let want = pair.1
    @test.assert_eq(base32_hex_encode(@utf8.encode(input)), want)
    @test.assert_eq(@utf8.decode(base32_hex_decode(want)), input)
  }
}

///|
test "unpadded encoding and decoding round-trip" {
  let cases = ["f", "fo", "foo", "foob", "fooba", "foobar", "Hello, MoonBit!"]
  for s in cases {
    let encoded = base32_encode_unpadded(@utf8.encode(s))
    @test.assert_eq(encoded.contains("="), false)
    @test.assert_eq(@utf8.decode(base32_decode(encoded)), s)
  }
}

///|
test "lowercase letters are rejected" {
  // Lowercase letters are not in the standard alphabet and must be rejected
  // rather than silently accepted.
  let rejected = try {
    ignore(base32_decode("my======"))
    false
  } catch {
    _ => true
  }
  @test.assert_eq(rejected, true)
}

///|
test "invalid character is rejected with position" {
  let e = @test.expect_error(fn() -> Unit raise Base32Error {
    ignore(base32_decode("M!ZXQ===="))
  })
  match e {
    InvalidCharacter(pos, c) => {
      @test.assert_eq(pos, 1)
      @test.assert_eq(c, '!')
    }
    _ => @test.fail("expected InvalidCharacter")
  }
}

///|
test "padding in the middle is rejected" {
  let e = @test.expect_error(fn() -> Unit raise Base32Error {
    ignore(base32_decode("M=XQ===="))
  })
  @test.assert_eq(e is InvalidPadding, true)
}

///|
test "wrong padding length is rejected" {
  let e = @test.expect_error(fn() -> Unit raise Base32Error {
    ignore(base32_decode("MY=====")) // 5 padding chars instead of 6
  })
  @test.assert_eq(e is InvalidPadding, true)
}

///|
test "impossible unpadded length is rejected" {
  let e = @test.expect_error(fn() -> Unit raise Base32Error {
    ignore(base32_decode("M")) // 1 data character cannot encode whole bytes
  })
  @test.assert_eq(e is InvalidPadding, true)
}

///|
test "non-zero trailing bits are rejected" {
  // "MY" encodes "f" with zero trailing bits; "MZ" carries non-zero trailing
  // bits that cannot decode to a whole byte and must be rejected.
  let e = @test.expect_error(fn() -> Unit raise Base32Error {
    ignore(base32_decode("MZ"))
  })
  @test.assert_eq(e is InvalidPadding, true)
}
