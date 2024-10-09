Here’s a documentation-style guide for your `cryptirust` package, taking inspiration from top Rust packages like Axum, Clap, and Actix, aiming for clarity, ease of use, and detailed examples. The goal is to make your package accessible and polished for other developers.

---

# Cryptirust

**Cryptirust** is a Rust library for generating highly customizable and pronounceable passwords. It provides a flexible API to create passphrases, word-based passwords, and sequences with symbols or numbers, with entropy calculation for each generated password.

The library is built around a `Generator` struct that uses a Markov chain-based approach to construct passwords based on predefined or custom token lists, allowing for fine-grained control over password structure and randomness.

## Features

- **Pronounceable Passwords**: Generate passwords or passphrases that are easy to pronounce and remember.
- **Entropy Calculation**: Automatically computes the entropy of each password generated.
- **Customizable Patterns**: Use symbols, numbers, words, or consonant-vowel (CV) sequences.
- **Custom Token Sets**: Define your own sets of tokens and control the depth of the Markov chain.
- **Flexible Generation**: Generate passphrases, CV words, or custom patterns including symbols, words, and digits.

## Example Usage

### 1. Create a Default Generator

The default generator uses the [EFF wordlist](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases) for generating secure and easy-to-remember passphrases.

```rust
use cryptirust::Generator;

fn main() {
    let mut generator = Generator::new();
    let (passphrase, entropy) = generator.gen_passphrase(4);
    println!("Generated passphrase: {}", passphrase);
    println!("Entropy: {:.2} bits", entropy);
}
```

### 2. Generate a Passphrase with Custom Depth

```rust
use cryptirust::Generator;

fn main() {
    let mut generator = Generator::new_custom(vec!["apple", "banana", "cherry"], 2);
    let (passphrase, entropy) = generator.gen_passphrase(5);
    println!("Generated passphrase: {}", passphrase);
    println!("Entropy: {:.2} bits", entropy);
}
```

### 3. Generate a Password from a Custom Pattern

Use a pattern string to create complex passwords:

- **`w`**: Lowercase word.
- **`W`**: Uppercase word.
- **`c`**: Lowercase character.
- **`C`**: Uppercase character.
- **`s`**: Symbol.
- **`d`**: Digit.

```rust
use cryptirust::Generator;

fn main() {
    let mut generator = Generator::new();
    let (password, entropy) = generator.gen_from_pattern("WcsdwW");
    println!("Generated password: {}", password);
    println!("Entropy: {:.2} bits", entropy);
}
```

### 4. Generate a Consonant-Vowel (CV) Word

This method generates a simple word with alternating consonants and vowels:

```rust
use cryptirust::Generator;

fn main() {
    let mut generator = Generator::new();
    let (cv_word, entropy) = generator.gen_cv_word(6);
    println!("Generated CV word: {}", cv_word);
    println!("Entropy: {:.2} bits", entropy);
}
```

---

## API Documentation

### `struct Generator`

The main structure for generating passwords.

#### Associated Functions

- **`fn new() -> Generator`**
  
  Creates a new generator using the default wordlist (EFF's word list) with a Markov chain depth of 3.

- **`fn new_custom(tokens: Vec<String>, chain_depth: usize) -> Generator`**

  Creates a new generator with a custom token set and a specified Markov chain depth.
  
  - `tokens`: A vector of words or tokens to use for password generation.
  - `chain_depth`: The depth of the Markov chain (how many preceding tokens are considered for generating the next token).

- **`fn new_he() -> Generator`**

  Similar to `new()`, but uses a Markov chain depth of 2 for quicker password generation at the expense of phonetic fidelity.

#### Methods

- **`fn gen_passphrase(&mut self, words: u64) -> (String, f64)`**

  Generates a passphrase of `words` length. Returns a tuple containing the passphrase and its entropy in bits.

  - `words`: Number of words in the passphrase.

- **`fn gen_from_pattern(&mut self, pattern: &str) -> (String, f64)`**

  Generates a password based on a user-defined pattern string. Returns the generated password and its entropy in bits.

  - `pattern`: A string representing the pattern to follow. E.g., `"Wcdd"`, where `W` is an uppercase word, `c` is a lowercase character, and `d` is a digit.

- **`fn gen_next_token(&mut self, seed: &str) -> (String, f64)`**

  Generates the next token in the sequence based on the given `seed`. Returns the token and its entropy.

  - `seed`: The current sequence of characters used to generate the next token.

- **`fn gen_word_length(&mut self) -> (usize, f64)`**

  Generates the length of the next word in a passphrase based on predefined length probabilities.

- **`fn gen_cv_word(&mut self, n: usize) -> (String, f64)`**

  Generates a word of length `n` consisting of alternating consonants and vowels. Returns the word and its entropy.

  - `n`: The desired length of the consonant-vowel word.

---

## Customization

The `Generator` can be customized by supplying your own list of tokens. For example, you could use a custom wordlist or a specific set of symbols.

```rust
let custom_tokens = vec![
    String::from("rust"),
    String::from("cargo"),
    String::from("ownership"),
];

let mut generator = Generator::new_custom(custom_tokens, 3);
let (password, entropy) = generator.gen_passphrase(4);
println!("Custom passphrase: {}", password);
```

---

## Performance Considerations

- For larger token sets or deeper Markov chains, the performance may decrease as the generator processes more possible transitions.

---

## License

Cryptirust is licensed under the MIT License.
