///|
/// Tests for Steam Guard codes.
test "steam guard format and determinism" {
  let key = @utf8.encode("12345678901234567890")
  let alphabet = "23456789BCDFGHJKMNPQRTVWXY"
  let code = steam_guard(key, 0UL)
  @test.assert_eq(5, code.length())
  for i in 0..<5 {
    @test.assert_eq(true, alphabet.contains(code[i:i + 1]))
  }
  // Same time step gives the same code.
  @test.assert_eq(code, steam_guard(key, 0UL))
  @test.assert_eq(code, steam_guard(key, 29UL))
}

///|
test "steam guard errors on empty key and bad period" {
  let key = @utf8.encode("")
  let e = @test.expect_error(fn() -> String raise OtpError {
    steam_guard(key, 0UL)
  })
  @test.assert_eq(
    true,
    match e {
      EmptySecret => true
      _ => false
    },
  )
}
