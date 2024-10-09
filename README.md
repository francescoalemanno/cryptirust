# Cryptirust
[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]
[![Discord chat][discord-badge]][discord-url]

[crates-badge]: https://img.shields.io/crates/v/cryptirust.svg
[crates-url]: https://crates.io/crates/cryptirust
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/francescoalemanno/cryptirust/blob/master/LICENSE

[API Docs](https://docs.rs/cryptirust/latest/cryptirust/)
<!-- cargo-sync-readme start -->

**Cryptirust** is a Rust library for generating highly customizable and pronounceable passwords. It provides a flexible API to create passphrases, word-based passwords, and sequences with symbols or numbers, with entropy calculation for each generated password.

The library is built around a `Generator` struct that uses a Markov chain-based approach to construct passwords based on predefined or custom token lists, allowing for fine-grained control over password structure and randomness.

## Features

- **Pronounceable Passwords**: Generate passwords or passphrases that are easy to pronounce and remember.
- **Entropy Calculation**: Automatically computes the entropy of each password generated.
- **Custom phonetic style**: Define your own sets of word-tokens and control the depth of the probabilistic model (Markov chain).
- **Flexible Generation**: Generate passphrases, or custom patterns including symbols, pseudo-words, and digits.

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