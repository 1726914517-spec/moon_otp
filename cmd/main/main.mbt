///|
/// Command line interface for moon_otp.
fn usage() -> Unit {
  println("moon_otp - HOTP/TOTP one-time passwords in MoonBit")
  println("")
  println("Usage:")
  println(
    "  moon_otp gen [--issuer <s>] [--account <s>] [--length <n>] [--algorithm SHA1|SHA256|SHA512] [--digits <n>] [--period <n>]",
  )
  println(
    "  moon_otp now --secret <base32> [--algorithm ..] [--digits <n>] [--period <n>]",
  )
  println(
    "  moon_otp hotp --secret <base32> --counter <n> [--algorithm ..] [--digits <n>]",
  )
  println(
    "  moon_otp uri --secret <base32> --issuer <s> --account <s> [--algorithm ..] [--digits <n>] [--period <n>]",
  )
  println("  moon_otp steam --secret <base32>")
  println("  moon_otp recovery [--count <n>]")
  println(
    "  moon_otp verify --secret <base32> --code <code> [--window <n>] [--algorithm ..]",
  )
}

///|
fn parse_flags(argv : Array[String]) -> Map[String, String] {
  let flags = Map::new()
  let mut i = 2
  while i < argv.length() {
    let token = argv[i]
    if token.has_prefix("--") {
      if i + 1 >= argv.length() {
        eprintln("missing value for flag: " + token)
        abort("bad arguments")
      }
      flags.set(token[2:].to_owned(), argv[i + 1])
      i += 2
    } else {
      eprintln("unexpected argument: " + token)
      abort("bad arguments")
    }
  }
  flags
}

///|
fn string_flag(
  flags : Map[String, String],
  name : String,
  default : String,
) -> String {
  match flags.get(name) {
    Some(v) => v
    None => default
  }
}

///|
fn int_flag(
  flags : Map[String, String],
  name : String,
  default : Int,
) -> Int raise @lib.OtpError {
  match flags.get(name) {
    Some(v) =>
      @string.parse_int(v) catch {
        _ => raise @lib.InvalidUri("invalid integer for --" + name + ": " + v)
      }
    None => default
  }
}

///|
fn algorithm_flag(
  flags : Map[String, String],
) -> @lib.HashAlgorithm raise @lib.OtpError {
  match flags.get("algorithm") {
    None => @lib.Sha1
    Some(v) if v == "SHA1" => @lib.Sha1
    Some(v) if v == "SHA256" => @lib.Sha256
    Some(v) if v == "SHA512" => @lib.Sha512
    Some(v) => raise @lib.InvalidUri("unknown algorithm: " + v)
  }
}

///|
fn decode_secret(flags : Map[String, String]) -> Bytes raise @lib.OtpError {
  match flags.get("secret") {
    Some(s) =>
      @lib.base32_decode(s) catch {
        _ => raise @lib.InvalidUri("--secret is not valid Base32")
      }
    None => raise @lib.InvalidUri("missing required --secret <base32>")
  }
}

///|
fn cmd_gen(flags : Map[String, String]) -> Unit raise @lib.OtpError {
  let length = int_flag(flags, "length", 20)
  let secret = @lib.generate_secret(length~)
  let issuer = string_flag(flags, "issuer", "Example")
  let account = string_flag(flags, "account", "user@example.com")
  let algorithm = algorithm_flag(flags)
  let digits = int_flag(flags, "digits", 6)
  let period = int_flag(flags, "period", 30)
  let otp : @lib.OtpAuth = {
    issuer,
    account,
    secret,
    algorithm,
    digits,
    period,
    otp_type: @lib.Totp,
    counter: 0UL,
  }
  println("Secret (Base32): " + @lib.base32_encode_unpadded(secret))
  println("otpauth URI:    " + @lib.otpauth_uri(otp))
  println(
    "Current code:   " + @lib.totp_now(algorithm, secret, digits~, period~),
  )
}

///|
fn cmd_now(flags : Map[String, String]) -> Unit raise @lib.OtpError {
  let secret = decode_secret(flags)
  let algorithm = algorithm_flag(flags)
  let digits = int_flag(flags, "digits", 6)
  let period = int_flag(flags, "period", 30)
  let code = @lib.totp_now(algorithm, secret, digits~, period~)
  // @env.now() returns milliseconds.
  let now_seconds = @env.now() / 1000UL
  let remaining = period.to_uint64() - now_seconds % period.to_uint64()
  println(code + " (" + remaining.to_string() + "s remaining)")
}

///|
fn cmd_hotp(flags : Map[String, String]) -> Unit raise @lib.OtpError {
  let secret = decode_secret(flags)
  let algorithm = algorithm_flag(flags)
  let digits = int_flag(flags, "digits", 6)
  let counter = match flags.get("counter") {
    Some(v) =>
      @string.parse_uint64(v) catch {
        _ => raise @lib.InvalidUri("invalid --counter: " + v)
      }
    None => raise @lib.InvalidUri("missing required --counter <n>")
  }
  println(@lib.hotp(algorithm, secret, counter, digits~))
}

///|
fn cmd_uri(flags : Map[String, String]) -> Unit raise @lib.OtpError {
  let secret = decode_secret(flags)
  let issuer = match flags.get("issuer") {
    Some(v) => v
    None => raise @lib.InvalidUri("missing required --issuer <s>")
  }
  let account = match flags.get("account") {
    Some(v) => v
    None => raise @lib.InvalidUri("missing required --account <s>")
  }
  let algorithm = algorithm_flag(flags)
  let digits = int_flag(flags, "digits", 6)
  let period = int_flag(flags, "period", 30)
  let otp : @lib.OtpAuth = {
    issuer,
    account,
    secret,
    algorithm,
    digits,
    period,
    otp_type: @lib.Totp,
    counter: 0UL,
  }
  println(@lib.otpauth_uri(otp))
}

///|
fn cmd_steam(flags : Map[String, String]) -> Unit raise @lib.OtpError {
  let secret = decode_secret(flags)
  println(@lib.steam_guard_now(secret))
}

///|
fn cmd_recovery(flags : Map[String, String]) -> Unit raise @lib.OtpError {
  let count = int_flag(flags, "count", 10)
  println("Recovery codes (each may be used once):")
  for code in @lib.generate_recovery_codes(count~) {
    println("  " + code)
  }
}

///|
fn cmd_verify(flags : Map[String, String]) -> Unit raise @lib.OtpError {
  let secret = decode_secret(flags)
  let algorithm = algorithm_flag(flags)
  let window = int_flag(flags, "window", 1)
  let code = match flags.get("code") {
    Some(v) => v
    None => raise @lib.InvalidUri("missing required --code <code>")
  }
  if @lib.totp_verify(algorithm, secret, code, window~) {
    println("OK")
  } else {
    println("FAIL")
    abort("verification failed")
  }
}

///|
fn main {
  let argv = @env.args()
  if argv.length() < 2 {
    usage()
    abort("")
  }
  let command = argv[1]
  let flags = parse_flags(argv)
  try {
    match command {
      "gen" => cmd_gen(flags)
      "now" => cmd_now(flags)
      "hotp" => cmd_hotp(flags)
      "uri" => cmd_uri(flags)
      "steam" => cmd_steam(flags)
      "recovery" => cmd_recovery(flags)
      "verify" => cmd_verify(flags)
      _ => {
        usage()
        abort("")
      }
    }
  } catch {
    e => {
      eprintln("error:")
      eprintln(e.to_repr())
      abort("")
    }
  }
}
