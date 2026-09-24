/// otpauth:// key URI support (the de-facto format used by Google
/// Authenticator and compatible apps).

///|
/// OTP type carried by an otpauth URI.
pub(all) enum OtpKind {
  /// Time-based one-time password.
  Totp
  /// Event/counter-based one-time password.
  Hotp
} derive(Eq, @debug.Debug)

///|
/// Parameters of an otpauth enrollment URI.
pub(all) struct OtpAuth {
  /// Provider or service name, e.g. "Acme Corp".
  issuer : String
  /// User account, e.g. "alice@example.com".
  account : String
  /// Raw shared-secret bytes.
  secret : Bytes
  /// HMAC hash algorithm.
  algorithm : HashAlgorithm
  /// Number of code digits.
  digits : Int
  /// Time step in seconds (TOTP).
  period : Int
  /// TOTP or HOTP.
  otp_type : OtpKind
  /// Initial counter (HOTP).
  counter : UInt64
}

///|
/// Create the default parameter set for a secret (TOTP, SHA-1, 6 digits,
/// 30 s).
pub fn OtpAuth::new(
  issuer : String,
  account : String,
  secret : Bytes,
) -> OtpAuth {
  {
    issuer,
    account,
    secret,
    algorithm: Sha1,
    digits: 6,
    period: 30,
    otp_type: Totp,
    counter: 0UL,
  }
}

///|
fn pct_encode(s : StringView) -> String {
  @percent.encode(s)
}

///|
fn pct_decode(s : StringView) -> String raise OtpError {
  @percent.decode(s) catch {
    _ => raise InvalidUri("bad percent encoding")
  }
}

///|
fn uri_algorithm_name(algorithm : HashAlgorithm) -> String {
  match algorithm {
    Sha1 => "SHA1"
    Sha256 => "SHA256"
    Sha512 => "SHA512"
  }
}

///|
fn algorithm_from_uri(s : StringView) -> HashAlgorithm? {
  if s == "SHA1" {
    Some(Sha1)
  } else if s == "SHA256" {
    Some(Sha256)
  } else if s == "SHA512" {
    Some(Sha512)
  } else {
    None
  }
}

///|
/// Build an `otpauth://` URI (TOTP or HOTP).
pub fn otpauth_uri(otp : OtpAuth) -> String raise OtpError {
  if otp.secret.length() == 0 {
    raise EmptySecret
  }
  if otp.digits < 1 || otp.digits > 8 {
    raise InvalidDigits(otp.digits)
  }
  let (type_name, extra_param) = match otp.otp_type {
    Totp => {
      if otp.period <= 0 {
        raise InvalidPeriod(otp.period)
      }
      ("totp", "&period=" + otp.period.to_string())
    }
    Hotp => ("hotp", "&counter=" + otp.counter.to_string())
  }
  let label = pct_encode(otp.issuer) + ":" + pct_encode(otp.account)
  let secret = base32_encode_unpadded(otp.secret)
  let query = "?secret=" +
    secret +
    "&issuer=" +
    pct_encode(otp.issuer) +
    "&algorithm=" +
    uri_algorithm_name(otp.algorithm) +
    "&digits=" +
    otp.digits.to_string() +
    extra_param
  "otpauth://" + type_name + "/" + label + query
}

///|
/// Parse an `otpauth://totp/` or `otpauth://hotp/` URI.
pub fn parse_otpauth_uri(uri : String) -> OtpAuth raise OtpError {
  let (otp_type, rest) = if uri.has_prefix("otpauth://totp/") {
    (Totp, uri["otpauth://totp/".length():].to_owned())
  } else if uri.has_prefix("otpauth://hotp/") {
    (Hotp, uri["otpauth://hotp/".length():].to_owned())
  } else {
    raise InvalidUri("not an otpauth://totp or otpauth://hotp URI")
  }
  let (label_view, query_view) = match rest.split_once("?") {
    Some(parts) => parts
    None => raise InvalidUri("missing query component")
  }
  // Label: "Issuer:account" or just "account".
  let (label_issuer, account_view) = match label_view.split_once(":") {
    Some((issuer, account)) => (Some(issuer), account)
    None => (None, label_view)
  }
  let account = pct_decode(account_view)
  // Query parameters.
  let mut secret_raw : StringView? = None
  let mut query_issuer : StringView? = None
  let mut algorithm = Sha1
  let mut digits = 6
  let mut period = 30
  let mut counter = 0UL
  for pair in query_view.split("&") {
    let (k, v) = match pair.split_once("=") {
      Some(parts) => parts
      None => raise InvalidUri("malformed query pair: " + pair.to_owned())
    }
    if k == "secret" {
      secret_raw = Some(v)
    } else if k == "issuer" {
      query_issuer = Some(v)
    } else if k == "algorithm" {
      match algorithm_from_uri(v) {
        Some(a) => algorithm = a
        None => raise InvalidUri("unknown algorithm: " + v.to_owned())
      }
    } else if k == "digits" {
      digits = @string.parse_int(v) catch {
        _ => raise InvalidUri("bad digits: " + v.to_owned())
      }
    } else if k == "period" {
      period = @string.parse_int(v) catch {
        _ => raise InvalidUri("bad period: " + v.to_owned())
      }
    } else if k == "counter" {
      counter = @string.parse_uint64(v) catch {
        _ => raise InvalidUri("bad counter: " + v.to_owned())
      }
    } else {
      ignore(())
    }
  }
  let secret_str = match secret_raw {
    Some(s) => s.to_owned()
    None => raise InvalidUri("missing secret parameter")
  }
  let secret = base32_decode(secret_str) catch {
    _ => raise InvalidUri("secret is not valid Base32")
  }
  let issuer = match query_issuer {
    Some(i) => pct_decode(i)
    None =>
      match label_issuer {
        Some(i) => pct_decode(i)
        None => ""
      }
  }
  { issuer, account, secret, algorithm, digits, period, otp_type, counter, }
}
