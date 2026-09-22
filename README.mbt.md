# moon_otp

A one-time password (OTP) library for [MoonBit], implementing HOTP and TOTP
from the ground up — no external crypto dependencies.

- **HOTP** — HMAC-based one-time passwords, [RFC 4226]
- **TOTP** — time-based one-time passwords, [RFC 6238]
- **HMAC** — keyed hashing, [RFC 2104], over SHA-1 / SHA-256 / SHA-512
- **SHA-1 / SHA-256 / SHA-512** — FIPS 180-4 hash implementations
- **Base32** — [RFC 4648], standard and Extended Hex alphabets
- **otpauth:// URIs** — build and parse the de-facto authenticator format
- **Secure secret generation** — backed by the platform CSPRNG
- A small command line tool for enrollment and code generation

Every algorithm is verified against the official RFC / NIST test vectors
(32 tests).

## Install

```bash
moon add username/moon_otp
```

Then import the root package:

```moonbit nocheck
///|
import {
  "username/moon_otp",
}
```

## Library usage

### TOTP (the common case)

```moonbit nocheck
///|
/// Generate a new shared secret and enroll a user.
let secret = generate_secret() // 20 random bytes

///|
let otp = {
  issuer: "Acme Corp",
  account: "alice@example.com",
  secret,
  algorithm: Sha1,
  digits: 6,
  period: 30,
}

///|
let uri = otpauth_uri(otp) // QR-code content for an authenticator app

///|
/// Produce the code for the current time, and verify a user-submitted code
/// with one step of clock drift tolerance.
let current = totp_now(Sha1, secret)

///|
let valid = current == submitted_code ||
  totp(Sha1, secret, now_seconds - 30) == submitted_code ||
  totp(Sha1, secret, now_seconds + 30) == submitted_code
```

### HOTP

```moonbit nocheck
let key = @utf8.encode("12345678901234567890")
hotp(Sha1, key, 0UL) // "755224"
hotp(Sha1, key, 1UL) // "287082"
```

### TOTP with SHA-256/SHA-512 and 8 digits

```moonbit nocheck
totp(Sha256, key256, 1111111109UL, digits=8) // "68084774"
totp(Sha512, key512, 1234567890UL, digits=8) // "93441116"
```

### Parsing an otpauth URI

```moonbit nocheck
///|
let otp = parse_otpauth_uri(uri)

///|
let code = totp_now(
  otp.algorithm,
  otp.secret,
  digits=otp.digits,
  period=otp.period,
)
```

All fallible functions raise the `OtpError` error set (invalid digits, empty
secret, malformed URI, unavailable random source, ...).

## CLI

Build and run with the MoonBit toolchain:

```bash
moon run cmd/main -- gen --issuer GitHub --account alice
```

```text
Secret (Base32): 2WEXWAJKI3EFXMXBI3NE2BIAIHE2UNGV
otpauth URI:    otpauth://totp/GitHub:alice?secret=...&issuer=GitHub&algorithm=SHA1&digits=6&period=30
Current code:   832873
```

Other commands:

```bash
# Current TOTP for an existing secret
moon run cmd/main -- now --secret 2WEXWAJKI3EFXMXBI3NE2BIAIHE2UNGV

# HOTP at a specific counter
moon run cmd/main -- hotp --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ --counter 0

# Build an otpauth URI from an existing secret
moon run cmd/main -- uri --secret <base32> --issuer GitHub --account alice --algorithm SHA256
```

## Testing

```bash
moon test
```

The suite contains 32 tests covering:

- FIPS 180-4 / NIST vectors for all three hashes (empty, `"abc"`, two-block)
- HMAC vectors from RFC 2202 (SHA-1) and RFC 4231 (SHA-256/512)
- The full HOTP Appendix D sequence (counters 0–9)
- The complete TOTP Appendix B table for SHA-1/256/512, including the
  8-digit values
- Base32 RFC 4648 vectors and strict padding validation
- otpauth URI round trips and malformed-URI errors
- Input validation and secure secret generation

## Project layout

```text
moon_otp/
├── base32.mbt        RFC 4648 Base32
├── sha1.mbt          SHA-1
├── sha256.mbt        SHA-256
├── sha512.mbt        SHA-512
├── digest.mbt        HashAlgorithm dispatch
├── hmac.mbt          HMAC (RFC 2104)
├── hotp.mbt          HOTP (RFC 4226)
├── totp.mbt          TOTP (RFC 6238)
├── secret.mbt        CSPRNG-backed secret generation
├── otpauth.mbt       otpauth:// URI build/parse
└── cmd/main/         Command line tool
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

[MoonBit]: https://www.moonbitlang.com/
[RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104
[RFC 4226]: https://www.rfc-editor.org/rfc/rfc4226
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648
[RFC 6238]: https://www.rfc-editor.org/rfc/rfc6238
