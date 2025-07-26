# Token Forge

**Token Forge** is a lightweight command-line tool for generating and verifying HMAC-signed tokens using Rust. It is inspired by the concept of JSON Web Tokens (JWT), but deliberately simpler and customized for learning, experimentation, and personal use.

This project is not meant for production environments. It exists as a fun and educational exploration of cryptographic primitives, CLI design, and Rust development best practices.

## Features

- Generate HMAC SHA-256 signed tokens from arbitrary JSON payloads
- Optional token expiration support
- CLI-driven interface with ergonomic flags
- Load payloads from file
- Inspect and verify token contents
- Built-in demo that walks through token generation, expiration, and decoding
- Full test suite covering common and edge scenarios
- CI support for GitHub, GitLab, and Bitbucket

## Project Structure

```
prodesquare-token-forge/
├── src/                    # Rust source code
├── tests/                  # Integration tests
├── .env.example            # Sample environment config
├── Cargo.toml              # Crate manifest
├── bitbucket-pipelines.yml
├── .gitlab-ci.yml
└── .github/workflows/
    └── rust.yml
```

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/prodesquare/token-forge.git
cd token-forge
```

2. Setup Environment Variables:

```bash
cp .env.example .env
```

3. Build:

```bash
cargo build --release
```

## Environment Variables

Token Forge **does not compile your secret into the binary**. This is intentional. You must provide the signing key (`SECRET`) at runtime via an environment variable.

There are two common ways to set it:

1. Temporary (per session):

You can export it in your shell before running the binary:

```bash
export SECRET="my_signing_key"
# run token-forge now
```

2. Persistent (per user/system):

Add it to your shell's configuration file (e.g., `.bashrc`, `.zshrc`, etc.):

```bash
export SECRET="my_signing_key"
```

You can also set it in your `~/.profile` or `~/.bash_profile` file.

## Usage

1. Copy the binary to a location in your `$PATH` or run directly from the project directory:

```bash
cp target/release/token-forge /usr/local/bin
token-forge --help
```

2. Generate a token:

```bash
token-forge generate --file <path_to_json_file> --expiry <expiration_in_seconds>
# OR USING SHORTHAND FLAGS
token-forge generate -f <path_to_json_file> -e <expiration_in_seconds>
```

Use `--verbose` (`-v`) to print timestamps (`iat`, `exp`) during token generation.

3. Decode a token:

```bash
token-forge decode --token <token>
# OR USING SHORTHAND FLAGS
token-forge decode -t <token>
```

Use `--verbose` (`-v`) to print timestamps (`iat`, `exp`) during token decoding.

4. Run the demo:

```bash
token-forge demo
```

## Development & Testing

To run tests:

```bash
cargo test
```

CI runs on:

- GitHub Actions
- GitLab CI
- Bitbucket Pipelines

All of them execute standard build and test steps using the latest Rust toolchain.

## Notes

- Token Forge uses a simplified format (`HS256` + custom header) and should not be confused with full JWT standards.
- All tokens are encoded using URL-safe base64 without padding.
- Only the custom `TOK` type is supported in headers to keep the validation strict and simple.

This tool is not designed with production security considerations in mind. Please use vetted libraries and standards like `jwt` for real-world use cases.

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0) - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

This project was built as a fun weekend experiment to better understand tokenization, base64 encoding, HMAC signing, and CLI ergonomics in Rust. Inspired loosely by JWTs, but intentionally lighter.

## Support

- BTC: `18Hd1waYh5uG6nWRboXGD3Q3vaPzWRMgQH`
- ETH: `0x90b3f1495724e9e6a18372cb939df1d7166337b9`
