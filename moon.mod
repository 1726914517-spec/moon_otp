// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "1726914517-spec/moon_otp"

version = "0.1.0"

readme = "README.mbt.md"

repository = "https://github.com/1726914517-spec/moon_otp"

license = "Apache-2.0"

keywords = [ "otp", "totp", "hotp", "hmac", "2fa", "base32", "otpauth" ]

preferred_target = "wasm"

description = "HOTP (RFC 4226) and TOTP (RFC 6238) one-time password library with Base32, otpauth:// URIs and a CLI."
