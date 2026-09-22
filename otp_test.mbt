///|
/// Tests for HOTP (RFC 4226 Appendix D), TOTP (RFC 6238 Appendix B),
/// secret generation and error handling.
test "hotp rfc4226 appendix d" {
  let key = @utf8.encode("12345678901234567890")
  let expected = [
    "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
    "399871", "520489",
  ]
  for i in 0..<10 {
    @test.assert_eq(expected[i], hotp(Sha1, key, i.to_uint64()))
  }
}

///|
test "totp rfc6238 sha1" {
  let key = @utf8.encode("12345678901234567890")
  let times = [
    59UL, 1111111109UL, 1111111111UL, 1234567890UL, 2000000000UL, 20000000000UL,
  ]
  let expected = [
    "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
  ]
  for i in 0..<6 {
    @test.assert_eq(expected[i], totp(Sha1, key, times[i], digits=8))
  }
}

///|
test "totp rfc6238 sha256" {
  let key = @utf8.encode("12345678901234567890123456789012")
  let times = [
    59UL, 1111111109UL, 1111111111UL, 1234567890UL, 2000000000UL, 20000000000UL,
  ]
  let expected = [
    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
  ]
  for i in 0..<6 {
    @test.assert_eq(expected[i], totp(Sha256, key, times[i], digits=8))
  }
}

///|
test "totp rfc6238 sha512" {
  let key = @utf8.encode(
    "1234567890123456789012345678901234567890123456789012345678901234",
  )
  let times = [
    59UL, 1111111109UL, 1111111111UL, 1234567890UL, 2000000000UL, 20000000000UL,
  ]
  let expected = [
    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
  ]
  for i in 0..<6 {
    @test.assert_eq(expected[i], totp(Sha512, key, times[i], digits=8))
  }
}

///|
test "hotp/totp validation errors" {
  let key = @utf8.encode("12345678901234567890")
  let e1 = @test.expect_error(fn() -> String raise OtpError {
    hotp(Sha1, key, 0UL, digits=0)
  })
  @test.assert_eq(
    true,
    match e1 {
      InvalidDigits(_) => true
      _ => false
    },
  )
  let e2 = @test.expect_error(fn() -> String raise OtpError {
    hotp(Sha1, @utf8.encode(""), 0UL)
  })
  @test.assert_eq(
    true,
    match e2 {
      EmptySecret => true
      _ => false
    },
  )
  let e3 = @test.expect_error(fn() -> String raise OtpError {
    totp(Sha1, key, 100UL, period=0)
  })
  @test.assert_eq(
    true,
    match e3 {
      InvalidPeriod(_) => true
      _ => false
    },
  )
}

///|
test "generated secret round trips through base32" {
  let secret = generate_secret()
  @test.assert_eq(20, secret.length())
  let encoded = generate_secret_base32()
  @test.assert_eq(20, base32_decode(encoded).length())
  let e1 = @test.expect_error(fn() -> Bytes raise OtpError {
    generate_secret(length=0)
  })
  @test.assert_eq(
    true,
    match e1 {
      InvalidSecretLength(_) => true
      _ => false
    },
  )
}
