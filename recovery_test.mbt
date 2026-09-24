///|
/// Tests for one-time recovery codes.
test "recovery codes format and uniqueness" {
  let codes = generate_recovery_codes()
  @test.assert_eq(10, codes.length())
  let seen = Set::new()
  for code in codes {
    // Default form: XXXX-XXXX.
    @test.assert_eq(9, code.length())
    @test.assert_eq("-", code[4:5].to_owned())
    seen.add(code)
  }
  @test.assert_eq(10, seen.length())
}

///|
test "recovery codes configurable shape" {
  let codes = generate_recovery_codes(count=3, groups=3, group_size=2)
  @test.assert_eq(3, codes.length())
  // XX-XX-XX => 8 characters.
  @test.assert_eq(8, codes[0].length())
}

///|
test "recovery codes reject bad parameters" {
  let e = @test.expect_error(fn() -> Array[String] raise OtpError {
    generate_recovery_codes(count=0)
  })
  @test.assert_eq(
    true,
    match e {
      InvalidUri(_) => true
      _ => false
    },
  )
}
