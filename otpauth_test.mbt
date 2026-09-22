///|
/// Tests for otpauth:// URI building and parsing.
fn sample() -> OtpAuth {
  let secret = @utf8.encode("12345678901234567890")
  let otp = OtpAuth::new("Example Corp", "alice@example.com", secret)
  otp
}

///|
test "otpauth uri exact string" {
  @test.assert_eq(
    "otpauth://totp/Example%20Corp:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20Corp&algorithm=SHA1&digits=6&period=30",
    otpauth_uri(sample()),
  )
}

///|
test "otpauth build/parse round trip" {
  let otp = sample()
  let uri = otpauth_uri(otp)
  let parsed = parse_otpauth_uri(uri)
  @test.assert_eq(otp.issuer, parsed.issuer)
  @test.assert_eq(otp.account, parsed.account)
  @test.assert_eq(otp.secret, parsed.secret)
  @test.assert_eq(otp.algorithm, parsed.algorithm)
  @test.assert_eq(otp.digits, parsed.digits)
  @test.assert_eq(otp.period, parsed.period)
}

///|
test "otpauth sha256/8 digits round trip" {
  let secret = @utf8.encode("12345678901234567890123456789012")
  let otp : OtpAuth = {
    issuer: "Acme",
    account: "bob",
    secret,
    algorithm: Sha256,
    digits: 8,
    period: 60,
  }
  let parsed = parse_otpauth_uri(otpauth_uri(otp))
  @test.assert_eq(@moon_otp.Sha256, parsed.algorithm)
  @test.assert_eq(8, parsed.digits)
  @test.assert_eq(60, parsed.period)
}

///|
test "otpauth label issuer without query issuer" {
  let uri = "otpauth://totp/GitHub:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30"
  let parsed = parse_otpauth_uri(uri)
  @test.assert_eq("GitHub", parsed.issuer)
  @test.assert_eq("bob", parsed.account)
}

///|
test "otpauth parse errors" {
  let e1 = @test.expect_error(fn() -> OtpAuth raise OtpError {
    parse_otpauth_uri("https://example.com")
  })
  @test.assert_eq(
    true,
    match e1 {
      InvalidUri(_) => true
      _ => false
    },
  )
  let e2 = @test.expect_error(fn() -> OtpAuth raise OtpError {
    parse_otpauth_uri("otpauth://totp/Issuer:bob?digits=6")
  })
  @test.assert_eq(
    true,
    match e2 {
      InvalidUri(_) => true
      _ => false
    },
  )
  let e3 = @test.expect_error(fn() -> OtpAuth raise OtpError {
    parse_otpauth_uri("otpauth://totp/Issuer:bob?secret=!!!")
  })
  @test.assert_eq(
    true,
    match e3 {
      InvalidUri(_) => true
      _ => false
    },
  )
  let e4 = @test.expect_error(fn() -> OtpAuth raise OtpError {
    parse_otpauth_uri(
      "otpauth://totp/Issuer:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
    )
  })
  @test.assert_eq(
    true,
    match e4 {
      InvalidUri(_) => true
      _ => false
    },
  )
}
