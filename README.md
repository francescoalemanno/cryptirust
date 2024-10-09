# Cryptirust
[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status](ci-badge)](ci-yml)

[crates-badge]: https://img.shields.io/crates/v/cryptirust.svg
[crates-url]: https://crates.io/crates/cryptirust
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/francescoalemanno/cryptirust/blob/master/LICENSE
[ci-badge]: https://github.com/francescoalemanno/cryptirust/actions/workflows/rust.yml/badge.svg?branch=master
[ci-yml]: https://github.com/francescoalemanno/cryptirust/actions/workflows/rust.yml

[API Docs](https://docs.rs/cryptirust/latest/cryptirust/)
<!-- cargo-sync-readme start -->

**Cryptirust** is a flexible and efficient Rust library for generating customizable, pronounceable passwords with entropy calculation. It leverages a Markov chain-based approach through its core `Generator` struct, allowing you to construct secure passphrases and word-based passwords from predefined or user-defined token lists. 

Designed to balance security, usability, and flexibility, Cryptirust offers fine-grained control over the structure and randomness of passwords. Whether you're creating simple, memorable passphrases or complex high-entropy passwords, Cryptirust provides an intuitive API to meet a range of password generation needs.

### Key Features

- **Pronounceable Passwords**: Create easy-to-pronounce, memorable passwords using phonetic patterns.
- **Entropy Calculation**: Automatically calculates and returns the entropy of each generated password, helping you gauge its strength.
- **Custom Token Support**: Define custom token sets and adjust the depth of the Markov chain model for even greater control over password structure.
- **Pattern Flexibility**: Generate passphrases, pseudo-words, and custom patterns that can include symbols, numbers, and more.

## Quick start

### 1. Create a Default Generator

The default generator uses the [EFF wordlist](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases) as a base for training the markov model which generates secure and easy-to-remember passphrases.

```rust
use cryptirust::Generator;

fn main() {
    let mut generator = Generator::new();
    let (passphrase, entropy) = generator.gen_passphrase(4);
    println!("Generated passphrase: {}", passphrase);
    println!("Entropy: {:.2} bits", entropy);
}
```

### 2. Generate a Password from a Custom Pattern

Use a pattern string to create complex passwords:

- **`w`**: Lowercase pseudo-word.
- **`W`**: Uppercase pseudo-word.
- **`c`**: Lowercase character.
- **`C`**: Uppercase character.
- **`s`**: Symbol.
- **`d`**: Digit.
- **`\`**: Escape next character.

```rust
use cryptirust::Generator;

fn main() {
    let mut generator = Generator::new();
    let (password, entropy) = generator.gen_from_pattern("WcsdwW");
    println!("Generated password: {}", password);
    println!("Entropy: {:.2} bits", entropy);
}
```

### 3. Generate a Passphrase with Custom Depth

```rust
use cryptirust::Generator;

fn main() {
    let mut generator = Generator::new_custom(vec!["apple".to_string(), "banana".to_string(), "cherry".to_string()], 2);
    let (passphrase, entropy) = generator.gen_passphrase(5);
    println!("Generated passphrase: {}", passphrase);
    println!("Entropy: {:.2} bits", entropy);
}
```

## Command Line Interface is included with the library

This CLI allows users to specify a pattern for the generated passphrases
and the number of passphrases to generate. The default pattern is "www",
and it generates a single passphrase if no arguments are provided.

### Usage

To run the CLI, first `cargo install cryptirust`, then use the following command:

```bash
cryptirust [PATTERN] [NUM]
```

- **PATTERN**: A string representing the desired structure of the generated
               passphrases, default is `w-c-s-d` (i.e. word-character-symbol-digit).
- **NUM**: The number of passphrases to generate. Must be a positive integer.
           Default is `5`.

### Examples

Generate one passphrase with the default pattern:
```bash
cryptirust

         1:     35.06   reschan-a-*-7
         2:     32.46   crusat-u-^-9
         3:     24.73   septi-s-*-9
         4:     37.20   proggilen-f-?-9
         5:     31.29   penhan-l---9
```

Generate five passphrases with a custom pattern:
```bash
cryptirust "www" 4

         1:     57.84   jitteri.choverfe.impure
         2:     67.58   cupanton.gustopiu.epical
         3:     67.49   renotyp.sharfishi.blammog
         4:     61.15   listings.chucke.placepsyc
```

## License

Cryptirust is licensed under the MIT License.


<!-- cargo-sync-readme end -->