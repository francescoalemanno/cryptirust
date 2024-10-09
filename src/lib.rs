//! # cryptirust
//!
//! `cryptirust` is a fast and flexible library for generating secure, pronounceable passwords.
//! It offers fine-tuned control over password generation, allowing you to customize patterns,
//! include symbols or numbers, and generate passphrases or words with high entropy.
//!
//! ## Features
//!
//! - **Customizable Passwords**: Create passwords using custom token patterns, passphrases, or consonant-vowel sequences.
//! - **High Entropy**: Ensure strong security by calculating the entropy of generated passwords.
//! - **Markov Chains**: Utilize customizable chain depths for generating password tokens based on probabilistic models.
//! - **ChaCha8 RNG**: Powered by a cryptographically secure random number generator for reliable randomness.
//! - **Flexible Patterns**: Use custom patterns for generating passwords, including symbols, digits, and letter case controls.
//!
//! ## Getting Started
//!
//! To begin generating passwords, create a `Generator` and customize it based on your needs.
//! Here's a quick example of generating a passphrase with 4 words:
//!
//! ```rust
//! use cryptirust::Generator;
//!
//! let mut generator = Generator::new();
//! let (passphrase, entropy) = generator.gen_passphrase(4);
//!
//! println!("Generated passphrase: {}", passphrase);
//! println!("Entropy: {} bits", entropy);
//! ```
//!
//! ## Custom Patterns
//!
//! Patterns allow you to define the structure of your password with specific placeholders:
//!
//! - `w`: a word from the word list
//! - `W`: a capitalized word
//! - `s`: a symbol (e.g., `@`, `#`, `%`)
//! - `d`: a digit (e.g., `0`, `1`, `9`)
//! - `c`: a lowercase token
//! - `C`: an uppercase token
//!
//! Example of generating a password using a custom pattern:
//!
//! ```rust
//! let mut generator = Generator::new();
//! let (password, entropy) = generator.gen_from_pattern("Ww-sd");
//!
//! println!("Generated password: {}", password);
//! println!("Entropy: {} bits", entropy);
//! ```
//!
//! ## High Entropy Mode
//!
//! `cryptirust` provides an option for generating passwords with increased entropy by utilizing a more compact Markov chain depth.
//! You can switch to **high entropy** mode to prioritize complexity over pronounceability:
//!
//! ```rust
//! let mut generator = Generator::new_he();
//! let (secure_pass, entropy) = generator.gen_passphrase(4);
//!
//! println!("High-entropy passphrase: {}", secure_pass);
//! println!("Entropy: {} bits", entropy);
//! ```
//!
//! ## Additional Functionality
//!
//! - Generate consonant-vowel sequences for balanced and pronounceable passwords.
//! - Customize the word list or token patterns to suit your application's requirements.
//!
//! ## Why Use cryptirust?
//!
//! `cryptirust` is built for developers seeking a balance between security, usability, and flexibility in password generation.
//! Whether you need a simple passphrase or a complex, high-entropy password, `cryptirust` gives you the tools to control the
//! process and ensure robust security.
//!
//! ## Contributing
//!
//! Contributions are welcome! Please check out the [repository](https://github.com/francescoalemanno/cryptirust) for guidelines.
//!
//! ## License
//!
//! This project is licensed under the MIT License.
//!
//! ## Command Line Interface is included with the library
//!
//! This CLI allows users to specify a pattern for the generated passphrases
//! and the number of passphrases to generate. The default pattern is "www",
//! and it generates a single passphrase if no arguments are provided.
//!
//! ### Usage
//!
//! To run the CLI, first `cargo install cryptirust`, then use the following command:
//!
//! ```bash
//! cryptirust [PATTERN] [NUM]
//! ```
//!
//! - **PATTERN**: A string representing the desired structure of the generated
//!                passphrases, default is `w-c-s-d` (i.e. word-character-symbol-digit).
//! - **NUM**: The number of passphrases to generate. Must be a positive integer.
//!            Default is `5`.
//!
//! ### Examples
//!
//! Generate one passphrase with the default pattern:
//! ```bash
//! cryptirust
//! 
//!          1:     35.06   reschan-a-*-7
//!          2:     32.46   crusat-u-^-9
//!          3:     24.73   septi-s-*-9
//!          4:     37.20   proggilen-f-?-9
//!          5:     31.29   penhan-l---9
//! ```
//!
//! Generate five passphrases with a custom pattern:
//! ```bash
//! cryptirust "www" 4
//! 
//!          1:     57.84   jitteri.choverfe.impure
//!          2:     67.58   cupanton.gustopiu.epical
//!          3:     67.49   renotyp.sharfishi.blammog
//!          4:     61.15   listings.chucke.placepsyc
//! ```

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
pub mod word_list;

/// `Generator` is the core struct responsible for generating customizable, pronounceable passwords.
///
/// It allows generating passwords or passphrases based on wordlists, patterns, and custom token
/// sets, and calculates the entropy of each generated password. The generator can be configured
/// to generate more entropic but less pronounceable passwords or simple, easier-to-pronounce ones.
///
/// # Features
///
/// - Generate passphrases from a wordlist (default: EFF wordlist).
/// - Use custom tokens and control the Markov chain depth for greater flexibility.
/// - Support for generating passwords from patterns (symbols, digits, etc.).
/// - Calculate the entropy of generated passwords.
/// - Generate consonant-vowel (CV) sequences for simple pronounceable words.
///
/// # Example Usage
///
/// ```rust
/// use cryptirust::Generator;
///
/// // Create a default generator and generate a 4-word passphrase
/// let mut generator = Generator::new();
/// let (passphrase, entropy) = generator.gen_passphrase(4);
/// println!("Generated passphrase: {}", passphrase);
/// println!("Entropy: {:.2} bits", entropy);
/// ```
///
/// # Performance
///
/// By default, the generator uses a Markov chain depth of 3, which balances pronounceability
/// and complexity. For faster generation of more complex (but less pronounceable) passwords,
/// use `Generator::new_he()`, which lowers the depth to 2.
///
/// # Customization
///
/// You can provide your own token sets and control the Markov chain depth using `new_custom()`.
///
/// ```rust
/// use cryptirust::Generator;
/// let custom_tokens = vec![
///     String::from("rust"),
///     String::from("cargo"),
///     String::from("ownership"),
/// ];
///
/// let mut generator = Generator::new_custom(custom_tokens, 2);
/// let (password, entropy) = generator.gen_passphrase(4);
/// println!("Custom passphrase: {}", password);
/// ```
pub struct Generator {
    rng: ChaCha8Rng,
    jump_table: HashMap<String, Distribution>,
    depth: usize,
}
impl Default for Generator {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents the distribution of tokens used to generate passwords.
///
/// `Distribution` is a core part of the password generation logic in the
/// `cryptirust` package. It holds the token frequency data, entropy values, and
/// other metadata necessary to create randomized sequences based on a Markov-like
/// transition model.
///
/// # Fields
///
/// - `tokens`: A `Vec<String>` that stores the individual tokens (characters, symbols, etc.)
///   that can be chosen at each step of password generation.
///   
/// - `entropies`: A `Vec<f64>` that records the entropy (in bits) associated with each
///   token, representing the uncertainty or randomness introduced when that token is selected.
///   
/// - `counts`: A `Vec<usize>` containing cumulative counts that act as a boundary system for
///   selecting tokens based on their probability. This is used to efficiently index tokens
///   during generation by comparing a random number with the cumulative counts.
///   
/// - `total`: The total number of transitions or token occurrences in the distribution,
///   used for normalizing probabilities when selecting tokens.
///
/// # Entropy Calculation
///
/// The entropy values stored in `entropies` are crucial for determining the security
/// of generated passwords. Each token's entropy is calculated as the negative log-base-2
/// of its selection probability.
///
/// In essence, `Distribution` ensures that token selection follows a non-uniform
/// probability distribution, allowing for flexible password generation patterns
/// with well-defined entropy characteristics.
///
/// # See Also
///
/// - [`Generator`](struct.Generator.html): The main struct responsible for generating
///   passwords using this `Distribution` model.
/// - [`gen_next_token`](struct.Generator.html#method.gen_next_token): Generates the next token
///   in the sequence based on the distribution's probabilities.
struct Distribution {
    tokens: Vec<String>,
    entropies: Vec<f64>,
    counts: Vec<usize>,
    total: usize,
}

impl Generator {
    pub fn new_custom(tokens: Vec<String>, chain_depth: usize) -> Generator {
        let rng = ChaCha8Rng::from_entropy();
        let jump_table = Generator::distill(tokens, chain_depth);

        Generator {
            rng,
            jump_table,
            depth: chain_depth,
        }
    }

    pub fn new() -> Generator {
        Generator::new_custom(word_list::eff::list(), 3)
    }

    pub fn new_he() -> Generator {
        Generator::new_custom(word_list::eff::list(), 2)
    }

    pub fn gen_passphrase(&mut self, words: u64) -> (String, f64) {
        return self.gen_from_pattern(&"w".repeat(words as usize));
    }

    /// Generates a password based on a given pattern, while calculating its entropy.
    ///
    /// The pattern string defines how the password is structured, where different
    /// characters in the pattern correspond to different token types:
    ///
    /// * `'w'` - Generates a word from the token list (lowercase).
    /// * `'W'` - Generates a word from the token list (capitalized).
    /// * `'s'` - Inserts a symbol from the predefined symbol set (`@#!$%&=?^+-*"`).
    /// * `'d'` - Inserts a digit from the set `0-9`.
    /// * `'c'` - Generates a char token using the markov chain.
    /// * `'C'` - Generates a char token, capitalized.
    ///
    /// Additionally, any literal character (e.g., `.` or `!`) can be inserted into the
    /// pattern, which will be directly appended to the password as is.
    ///
    /// The method also supports escape sequences (`\`) to treat characters as literals,
    /// allowing pattern symbols like `'w'` or `'s'` to be included in the final password without
    /// triggering token generation.
    ///
    /// # Parameters
    ///
    /// * `pattern`: A string that defines the structure of the generated password. Each character
    /// in the string corresponds to a token type, symbol, or literal.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    ///
    /// * `String`: The generated password based on the given pattern.
    /// * `f64`: The estimated entropy of the generated password, calculated using the log base 2 of the number
    /// of possible outcomes for each token.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cryptirust::Generator;
    /// let mut gen = Generator::new();
    /// let (password, entropy) = gen.gen_from_pattern("wWsdC");
    /// println!("Generated password: {}, Entropy: {}", password, entropy);
    /// ```
    ///
    /// In this example, the pattern `"wWsdC"` would generate a password such as `"wordWORD5@Q"`,
    /// with its corresponding entropy value.
    ///
    /// # Panic
    ///
    /// Panics if the internal random number generator fails to produce a valid token
    /// or length value for the password generation process.
    ///
    /// # Performance
    ///
    /// The performance of this method depends on the length of the input pattern and
    /// the complexity of tokens defined in the jump table. Deeper chain depths or longer
    /// patterns may result in higher processing time.
    pub fn gen_from_pattern(&mut self, pattern: &str) -> (String, f64) {
        let mut passphrase = String::new();
        let mut entropy = 0.0;
        let mut iter = pattern.chars().peekable();

        loop {
            let cs = iter.next();
            if let Some(c) = cs {
                if c == '\\' {
                    passphrase.push(iter.next().unwrap_or('X'));
                    continue;
                }
                match c {
                    'w' | 'W' => {
                        let (mut head, mut h_head) = self.gen_next_token("");
                        let (leng, h_leng) = self.gen_word_length();
                        if c == 'W' {
                            head = head.to_uppercase();
                        }
                        while head.len() < leng {
                            let (nc, nh) = self.gen_next_token(&head.to_lowercase());
                            head.push_str(&nc);
                            h_head += nh;
                        }
                        passphrase.push_str(&head);
                        if iter.peek().unwrap_or(&'X') == &'w' {
                            // this is needed to avoid the case that 2 pseudo-words combine into 1, altering the entropy
                            passphrase.push('.');
                        }
                        entropy += h_head + h_leng;
                    }
                    's' | 'd' => {
                        let symbols = if c == 's' {
                            "@#!$%&=?^+-*\""
                        } else {
                            "0987654321"
                        };
                        let d = self.rng.gen_range(0..symbols.len());
                        passphrase.push(symbols.chars().nth(d).unwrap());
                        entropy += (symbols.len() as f64).log2();
                    }
                    'c' | 'C' => {
                        let (tok, h) = self.gen_next_token(&passphrase.to_lowercase());
                        if c == 'C' {
                            passphrase.push_str(&tok.to_uppercase());
                        } else {
                            passphrase.push_str(&tok);
                        }
                        entropy += h;
                    }
                    _ => {
                        passphrase.push(c);
                    }
                }
            } else {
                break;
            }
        }

        (passphrase, entropy)
    }

    /// Generates the next token in a sequence, based on the current seed and internal state.
    ///
    /// This method uses a Markov chain approach to predict the next token in the sequence,
    /// leveraging the internal `jump_table` that was distilled from the token corpus.
    ///
    /// The `seed` parameter is used as a starting point for the token generation. The method
    /// will look up the most recent characters (up to the chain depth) from the seed to
    /// determine the next likely token. If no match is found for the current sequence, the
    /// method will progressively reduce the seed size until a match is located or all
    /// options are exhausted.
    ///
    /// # Arguments
    ///
    /// * `seed` - A string slice representing the current sequence of characters, used to
    ///            determine the next token in the Markov chain.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * `String` - The next token in the sequence, generated based on the internal state
    ///              and the given seed.
    /// * `f64` - The entropy associated with the generated token, indicating the randomness
    ///           or unpredictability of the token.
    ///
    /// # Panics
    ///
    /// This function does not panic. In cases where no match is found in the `jump_table`,
    /// the method will continue reducing the seed until it finds a match or returns an
    /// empty string.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use cryptirust::Generator;
    /// let mut generator = Generator::new();
    /// let (token, entropy) = generator.gen_next_token("he");
    /// println!("Next token: {}, Entropy: {}", token, entropy);
    /// ```
    ///
    /// This example demonstrates how to generate the next token in a sequence starting with
    /// the seed `"he"`. The method returns both the token and its associated entropy.
    pub fn gen_next_token(&mut self, seed: &str) -> (String, f64) {
        let mut tok = seed.to_lowercase();
        loop {
            let depth = std::cmp::min(tok.len(), self.depth);
            let sub_tok = &tok[tok.len() - depth..];
            if let Some(tr) = self.jump_table.get(sub_tok) {
                let n = self.rng.gen_range(0..tr.total);
                for (i, v) in tr.counts.iter().enumerate() {
                    if n < *v {
                        return (tr.tokens[i].clone(), tr.entropies[i]);
                    }
                }
            }
            tok = tok[1..].to_string();
        }
    }

    pub fn gen_word_length(&mut self) -> (usize, f64) {
        if let Some(tr) = self.jump_table.get("LENGTHS") {
            let n = self.rng.gen_range(0..tr.total);
            for (i, v) in tr.counts.iter().enumerate() {
                if n < *v {
                    return (tr.tokens[i].parse::<usize>().unwrap(), tr.entropies[i]);
                }
            }
        }
        panic!("Unexpected random number for word length");
    }

    pub fn gen_cv_word(&mut self, n: usize) -> (String, f64) {
        const CONSONANTS: &str = "qwrtpsdfgjklzxcvbnm";
        const VOWELS: &str = "aeiou";
        let mut entropy = 1.0;
        let mut word = String::new();
        let (mut cons, mut vowe) = if self.rng.gen_bool(0.5) {
            (VOWELS, CONSONANTS)
        } else {
            (CONSONANTS, VOWELS)
        };
        for _ in 0..n {
            word.push(cons.chars().nth(self.rng.gen_range(0..cons.len())).unwrap());
            entropy += (cons.len() as f64).log2();
            (cons, vowe) = (vowe, cons);
        }
        (word, entropy)
    }

    fn distill(tokens: Vec<String>, depth: usize) -> HashMap<String, Distribution> {
        let mut transition_matrix: HashMap<String, HashMap<String, usize>> = HashMap::new();

        let put = |str: &str, r: &str, matrix: &mut HashMap<String, HashMap<String, usize>>| {
            matrix
                .entry(str.to_string())
                .or_default()
                .entry(r.to_string())
                .and_modify(|count| *count += 1)
                .or_insert(1);
        };

        for w in tokens.iter() {
            let chars: Vec<char> = w.to_lowercase().chars().collect();
            if chars.is_empty() {
                continue;
            }
            put("LENGTHS", &chars.len().to_string(), &mut transition_matrix);

            for i in 0..std::cmp::min(depth, chars.len()) {
                put(
                    &chars[..i].iter().collect::<String>(),
                    &chars[i].to_string(),
                    &mut transition_matrix,
                );
            }
            for i in 0..chars.len().saturating_sub(depth) {
                put(
                    &chars[i..i + depth].iter().collect::<String>(),
                    &chars[i + depth].to_string(),
                    &mut transition_matrix,
                );
            }
        }

        let mut dist_trans_matrix = HashMap::new();
        for (k, rfreq) in transition_matrix.into_iter() {
            let total: usize = rfreq.values().sum();
            let mut counts = Vec::new();
            let mut tokens = Vec::new();
            let mut entropies = Vec::new();
            let mut cum = 0;

            for (token, &freq) in rfreq.iter() {
                let p = freq as f64 / total as f64;
                cum += freq;
                entropies.push(-p.log2());
                counts.push(cum);
                tokens.push(token.clone());
            }

            dist_trans_matrix.insert(
                k,
                Distribution {
                    tokens,
                    entropies,
                    counts,
                    total,
                },
            );
        }

        dist_trans_matrix
    }
}
