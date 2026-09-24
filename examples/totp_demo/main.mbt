///|
/// Runnable demo: HOTP/TOTP vectors and an otpauth enrollment round trip.
///
/// Run with: moon run examples/totp_demo
fn section(title : String) -> Unit {
  println("")
  println("== " + title + " ==")
}

///|
fn main raise {
  // 1. HOTP RFC 4226 Appendix D.
  section("HOTP (RFC 4226 Appendix D, key \"12345678901234567890\")")
  let key = @utf8.encode("12345678901234567890")
  for counter in 0..<10 {
    println(
      "counter \{counter}: " + @lib.hotp(@lib.Sha1, key, counter.to_uint64()),
    )
  }

  // 2. TOTP RFC 6238 Appendix B at fixed timestamps.
  section("TOTP (RFC 6238 Appendix B, 8 digits)")
  let key256 = @utf8.encode("12345678901234567890123456789012")
  let key512 = @utf8.encode(
    "1234567890123456789012345678901234567890123456789012345678901234",
  )
  let timestamps : FixedArray[UInt64] = [
    59UL, 1111111109UL, 1234567890UL, 2000000000UL,
  ]
  for t in timestamps {
    println(
      "t=\{t}  SHA1=" +
      @lib.totp(@lib.Sha1, key, t, digits=8) +
      "  SHA256=" +
      @lib.totp(@lib.Sha256, key256, t, digits=8) +
      "  SHA512=" +
      @lib.totp(@lib.Sha512, key512, t, digits=8),
    )
  }

  // 3. Enroll a new user: secret + otpauth URI, then parse it back.
  section("Enrollment round trip")
  let secret = @lib.generate_secret()
  let otp : @lib.OtpAuth = {
    issuer: "Acme Corp",
    account: "alice@example.com",
    secret,
    algorithm: @lib.Sha256,
    digits: 6,
    period: 30,
    otp_type: @lib.Totp,
    counter: 0UL,
  }
  let uri = @lib.otpauth_uri(otp)
  println("URI: " + uri)
  let parsed = @lib.parse_otpauth_uri(uri)
  println(
    "parsed issuer=\{parsed.issuer} account=\{parsed.account} digits=\{parsed.digits}",
  )
  println("current code: " + @lib.totp_now(parsed.algorithm, parsed.secret))
}
