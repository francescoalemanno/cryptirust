# Cryptirust

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

## License

Cryptirust is licensed under the MIT License.


<!-- cargo-sync-readme end -->