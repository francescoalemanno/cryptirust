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
    let mut generator = Generator::new_custom(word_list::eff::list(), 2);
    let (passphrase, entropy) = generator.gen_from_pattern("w.w.w.w");;
    println!("Generated passphrase: {}", passphrase);
    println!("Entropy: {:.2} bits", entropy);
}
```

## Command Line Interface is included with the library

This CLI allows users to specify a pattern for the generated passphrases, the number
of passphrases to generate and the depth of the markov model.

### Usage

To run the CLI, first `cargo install cryptirust`, then use the following command:

```bash
cryptirust [PATTERN] [NUM] [DEPTH]
```

- **PATTERN**: A string representing the desired structure of the generated
               passphrases, default is `w-c-s-d` (i.e. word-token-symbol-digit).
- **NUM**: The number of passphrases to generate. Must be a positive integer.
           Default is `5`.
- **DEPTH**: The depth of the markov model. Must be a positive integer.
           Default is `3`.

### Examples

Generate five passphrases with the default pattern:
```bash
cryptirust

       n.     log2(guesses)     secret
        1              29.83    stingly-rak-+-5
        2              34.93    attinge-roy-+-5
        3              26.01    whomever-sta-"-3
        4              31.29    laddering-gre-^-5
        5              30.09    renditzy-sha-%-5
```

Generate six passphrases with a custom pattern "w.w.w" and a custom depth 2:
```bash
cryptirust w.w.w 6 2
       n.     log2(guesses)     secret
        1              57.60    gontex.atiness.unteet
        2              67.70    casuperl.cacharne.aneyway
        3              60.03    choomeg.deflanth.nessagre
        4              53.64    vishelaw.gedity.wildness
        5              58.19    dulays.frishea.queure
        6              56.36    partifie.deligeom.refullyi
```

## License

Cryptirust is licensed under the MIT License.


<!-- cargo-sync-readme end -->
