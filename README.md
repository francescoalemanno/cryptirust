# Cryptirust
[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][ci-badge]][ci-url]
[![API Docs][docs-badge]][docs-url]

[crates-badge]: https://img.shields.io/crates/v/cryptirust.svg
[crates-url]: https://crates.io/crates/cryptirust
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/francescoalemanno/cryptirust/blob/master/LICENSE
[ci-badge]: https://github.com/francescoalemanno/cryptirust/actions/workflows/rust.yml/badge.svg?branch=master
[ci-url]: https://github.com/francescoalemanno/cryptirust/actions/workflows/rust.yml
[docs-badge]: https://img.shields.io/badge/API-Docs-blue
[docs-url]: https://docs.rs/cryptirust/latest/cryptirust

<!-- cargo-sync-readme start -->

**Cryptirust** is a flexible and efficient Rust library for generating customizable, pronounceable passwords with entropy calculation. It leverages a Markov chain-based approach through its core `Generator` struct, allowing you to construct secure passphrases and word-based passwords from predefined or user-defined token lists.

Designed to balance security, usability, and flexibility, Cryptirust offers fine-grained control over the structure and randomness of passwords. Whether you're creating simple, memorable passphrases or complex high-entropy passwords, Cryptirust provides an intuitive API to meet a range of password generation needs.

### Key Features

- **Pronounceable Passwords**: Create easy-to-pronounce, memorable passwords using phonetic patterns.
- **Entropy Calculation**: Automatically calculates and returns the entropy of each generated password, helping you gauge its strength.
- **Custom Token Support**: Define custom token sets and adjust the depth of the Markov chain model for even greater control over password structure.
- **Pattern Flexibility**: Generate passphrases, pseudo-words, and custom patterns that can include symbols, numbers, and more.
- **CLI**: most functions of cryptirust are easily accessible from [`Crypticli`](../crypticli/index.html).

## Quick start

### 1. Generate a Password from a Custom Pattern

Use a pattern string to create complex passwords:

- **`c`**: Lowercase token.
- **`C`**: Uppercase token.
- **`w`**: Lowercase word.
- **`W`**: Uppercase word.
- **`s`**: Symbol.
- **`d`**: Digit.
- **`\`**: Escape next character.

```rust
use cryptirust::Generator;

fn main() {
    let mut generator = Generator::new();
    let (password, entropy) = generator.gen_from_pattern("cccsd");
    println!("Generated password: {}", password);
    println!("Entropy: {:.2} bits", entropy);
}
```

### 2. Generate a Passphrase with Custom Depth

```rust
use cryptirust::*;

fn main() {
    let mut generator = Generator::new_custom(word_list::eff::list(), 2).unwrap();
    let (passphrase, entropy) = generator.gen_from_pattern("w.w.w.w");;
    println!("Generated passphrase: {}", passphrase);
    println!("Entropy: {:.2} bits", entropy);
}
```

## License

Cryptirust is licensed under the MIT License.


<!-- cargo-sync-readme end -->
