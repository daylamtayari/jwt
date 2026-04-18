# jwt

Simple dependency-free, pipeline-friendly CLI utility to decode and verify JWTs

You can extract the parts as well as check the expiration and signature, with the utility exiting with code 1 if unsuccessful.

## Installation

### Go Install

```
go install github.com/daylamtayari/jwt@latest
```

### Binaries

You can download and use the pre-built binaries that are in the release tab: https://github.com/daylamtayari/jwt/releases

## Usage

```
Usage: jwt [command] [options] <jwt>

JWT can be passed as an argument or via stdin.

Commands:
  decode              Decode a JWT and output as JSON (default)
  data, payload       Output the payload
  header, headers     Output the headers
  sig                 Output the decoded signature bytes
  verify              Verify the signature
  valid               Check if the JWT is valid

Options:
  -k, --key <key>     Key for signature verification (file path or raw value)
  -h, --help          Show this help message

Examples:
  jwt <jwt>
  jwt decode <jwt>
  echo <jwt> | jwt data
  jwt verify -k secret <jwt>
  jwt valid <jwt>
  jwt valid -k secret <jwt>
```

## Examples

```bash
$ jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NTcxMTE2NH0.Z2v6IcVjGzlk8SaqBS3md68bXsfxkFs_3cIWasWTzGU
{"header":{"alg":"HS256","typ":"JWT"},"payload":{"admin":true,"iat":1775711164,"name":"John Doe","sub":"1234567890"},"signature":"Z2v6IcVjGzlk8SaqBS3md68bXsfxkFs_3cIWasWTzGU"}

$ jwt data eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3NTcxMTE2NH0.dqJP2rWcxYC5JxVgbHSx1KhCFKdcpBz0HmttLGVjpKs 
{"admin":true,"iat":1675711164,"name":"John Doe","sub":"1234567890"}

$ jwt valid eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MTY3NTcxMTE2NH0.iTZh1kCGj_Lv8vHIA1gxuuWpEQuhrgmd8O5EjP2KxxM
JWT is expired # exit 1

$ jwt valid eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30
true

$ jwt verify  --key a-string-secret-at-least-256-bits-long eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30
true
```

## License

This project is licensed under the MIT license.
