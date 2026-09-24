# moon_otp

A one-time password (OTP) library for [MoonBit], implementing HOTP and TOTP
from the ground up — no external crypto dependencies.

- **HOTP** — HMAC-based one-time passwords, [RFC 4226]
- **TOTP** — time-based one-time passwords, [RFC 6238]
- **HMAC** — keyed hashing, [RFC 2104], over SHA-1 / SHA-256 / SHA-512
- **SHA-1 / SHA-256 / SHA-512** — FIPS 180-4 hash implementations
- **Base32** — [RFC 4648], standard and Extended Hex alphabets
- **otpauth:// URIs** — build and parse the de-facto authenticator format
- **Steam Guard** — five-character Steam mobile authenticator codes
- **Recovery codes** — one-time backup codes for account recovery
- **HOTP resync** — counter resynchronization per RFC 4226 §7.4
- **Secure secret generation** — backed by the platform CSPRNG
- A small command line tool for enrollment and code generation

Every algorithm is verified against the official RFC / NIST test vectors
(40 tests).

## Install

```bash
moon add 1726914517-spec/moon_otp
```

Then import the root package:

```moonbit nocheck
///|
import {
  "1726914517-spec/moon_otp",
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

///|
/// The same drift-tolerant check is provided directly:
let ok = totp_verify(Sha1, secret, submitted_code)
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

### Steam Guard and recovery codes

```moonbit nocheck
///|
let steam_code = steam_guard_now(secret) // e.g. "YHBCW"

///|
let recovery = generate_recovery_codes() // 10 codes like "PJKP-Y94J"
```

### HOTP counter resynchronization (RFC 4226 §7.4)

```moonbit nocheck
///|
/// Client drifted ahead: it submitted codes for counters 2 and 3.
match hotp_resync(Sha1, key, server_counter, code1, code2, window=5) {
  Some(new_counter) => // persist new_counter
  None => // reject
}
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
# Current TOTP with seconds remaining in the step
moon run cmd/main -- now --secret 2WEXWAJKI3EFXMXBI3NE2BIAIHE2UNGV

# HOTP at a specific counter
moon run cmd/main -- hotp --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ --counter 0

# Build an otpauth URI from an existing secret
moon run cmd/main -- uri --secret <base32> --issuer GitHub --account alice --algorithm SHA256

# Steam Guard code
moon run cmd/main -- steam --secret <base32>

# One-time recovery codes
moon run cmd/main -- recovery --count 10

# Verify a code (exit 0 on success, 1 on failure)
moon run cmd/main -- verify --secret <base32> --code 123456 --window 1
```

## Testing

```bash
moon test
```

The suite contains 40 tests covering:

- FIPS 180-4 / NIST vectors for all three hashes (empty, `"abc"`, two-block)
- HMAC vectors from RFC 2202 (SHA-1) and RFC 4231 (SHA-256/512)
- The full HOTP Appendix D sequence (counters 0–9)
- The complete TOTP Appendix B table for SHA-1/256/512, including the
  8-digit values
- Base32 RFC 4648 vectors and strict padding validation
- otpauth URI round trips for both TOTP and HOTP, and malformed-URI errors
- Steam Guard format, recovery codes and HOTP resynchronization
- Drift-tolerant `totp_verify`, input validation and secret generation

## Project layout

```text
moon_otp/
├── base32.mbt        RFC 4648 Base32
├── sha1.mbt          SHA-1
├── sha256.mbt        SHA-256
├── sha512.mbt        SHA-512
├── digest.mbt        HashAlgorithm dispatch
├── hmac.mbt          HMAC (RFC 2104)
├── hotp.mbt          HOTP (RFC 4226) + resync
├── totp.mbt          TOTP (RFC 6238)
├── steam.mbt         Steam Guard codes
├── recovery.mbt      One-time recovery codes
├── secret.mbt        CSPRNG-backed secret generation
├── otpauth.mbt       otpauth:// URI build/parse (TOTP + HOTP)
└── cmd/main/         Command line tool
```

## Relation to existing packages

moon_otp is a focused OTP library. Related registry packages overlap with
individual building blocks but do not provide a complete, dedicated OTP
solution:

- **Q30399/moonvault** is a broad password-hashing/crypto suite. Its published
  0.1.0 covers TOTP generation/verification and URI building (with no HOTP
  function); its unreleased main branch adds HOTP, but `totp_now` and
  `totp_verify` pass a hardcoded timestamp 0 and never read the clock. moon_otp
  provides the missing, correct pieces:
  - otpauth:// URI *parsing* — moonvault only builds URIs (without
    algorithm/digits/period parameters or percent encoding);
  - a command line tool with gen/now/hotp/uri;
  - correct current-time TOTP with a configurable drift window;
  - RFC-verified HOTP and the complete RFC vector suites (HOTP Appendix D,
    TOTP Appendix B across SHA-1/256/512).
- **Tigls/mb-hmac** provides HMAC; moon_otp uses its own HMAC because the OTP
  layer requires all three hash algorithms and tight control of block sizes.
- **yyjeqhc/base32** and **Lfan-ke/basex** provide Base32; moon_otp includes
  its own decoder to validate OTP secrets without an extra dependency.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

[MoonBit]: https://www.moonbitlang.com/
[RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104
[RFC 4226]: https://www.rfc-editor.org/rfc/rfc4226
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648
[RFC 6238]: https://www.rfc-editor.org/rfc/rfc6238
