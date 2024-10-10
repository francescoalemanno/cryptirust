//! **Cryptirust** is a flexible and efficient Rust library for generating customizable, pronounceable passwords with entropy calculation. It leverages a Markov chain-based approach through its core `Generator` struct, allowing you to construct secure passphrases and word-based passwords from predefined or user-defined token lists.
//!
//! Designed to balance security, usability, and flexibility, Cryptirust offers fine-grained control over the structure and randomness of passwords. Whether you're creating simple, memorable passphrases or complex high-entropy passwords, Cryptirust provides an intuitive API to meet a range of password generation needs.
//!
//! ### Key Features
//!
//! - **Pronounceable Passwords**: Create easy-to-pronounce, memorable passwords using phonetic patterns.
//! - **Entropy Calculation**: Automatically calculates and returns the entropy of each generated password, helping you gauge its strength.
//! - **Custom Token Support**: Define custom token sets and adjust the depth of the Markov chain model for even greater control over password structure.
//! - **Pattern Flexibility**: Generate passphrases, pseudo-words, and custom patterns that can include symbols, numbers, and more.
//!
//! ## Quick start
//!
//! ### 1. Generate a Password from a Custom Pattern
//!
//! Use a pattern string to create complex passwords:
//!
//! - **`c`**: Lowercase token.
//! - **`C`**: Uppercase token.
//! - **`w`**: Lowercase word.
//! - **`W`**: Uppercase word.
//! - **`s`**: Symbol.
//! - **`d`**: Digit.
//! - **`\`**: Escape next character.
//!
//! ```rust
//! use cryptirust::Generator;
//!
//! fn main() {
//!     let mut generator = Generator::new();
//!     let (password, entropy) = generator.gen_from_pattern("cccsd");
//!     println!("Generated password: {}", password);
//!     println!("Entropy: {:.2} bits", entropy);
//! }
//! ```
//!
//! ### 2. Generate a Passphrase with Custom Depth
//!
//! ```rust
//! use cryptirust::*;
//!
//! fn main() {
//!     let mut generator = Generator::new_custom(word_list::eff::list(), 2);
//!     let (passphrase, entropy) = generator.gen_from_pattern("w.w.w.w");;
//!     println!("Generated passphrase: {}", passphrase);
//!     println!("Entropy: {:.2} bits", entropy);
//! }
//! ```
//!
//! ## Command Line Interface is included with the library
//!
//! This CLI allows users to specify a pattern for the generated passphrases, the number
//! of passphrases to generate and the depth of the markov model.
//!
//! ### Usage
//!
//! To run the CLI, first `cargo install cryptirust`, then use the following command:
//!
//! ```bash
//! cryptirust [PATTERN] [NUM] [DEPTH]
//! ```
//!
//! - **PATTERN**: A string representing the desired structure of the generated
//!                passphrases, default is `w-c-s-d` (i.e. word-token-symbol-digit).
//! - **NUM**: The number of passphrases to generate. Must be a positive integer.
//!            Default is `5`.
//! - **DEPTH**: The depth of the markov model. Must be a positive integer.
//!            Default is `3`.
//!
//! ### Examples
//!
//! Generate five passphrases with the default pattern:
//! ```bash
//! cryptirust
//!
//!        n.     log2(guesses)     secret
//!         1              29.83    stingly-rak-+-5
//!         2              34.93    attinge-roy-+-5
//!         3              26.01    whomever-sta-"-3
//!         4              31.29    laddering-gre-^-5
//!         5              30.09    renditzy-sha-%-5
//! ```
//!
//! Generate six passphrases with a custom pattern "w.w.w" and a custom depth 2:
//! ```bash
//! cryptirust w.w.w 6 2
//!        n.     log2(guesses)     secret
//!         1              57.60    gontex.atiness.unteet
//!         2              67.70    casuperl.cacharne.aneyway
//!         3              60.03    choomeg.deflanth.nessagre
//!         4              53.64    vishelaw.gedity.wildness
//!         5              58.19    dulays.frishea.queure
//!         6              56.36    partifie.deligeom.refullyi
//! ```
//!
//! ## License
//!
//! Cryptirust is licensed under the MIT License.
//!
#[doc = include_str!("../README.md")]
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
///
/// # Example Usage
///
/// ```rust
/// use cryptirust::Generator;
///
/// // Create a default generator and generate a 4-word passphrase
/// let mut generator = Generator::new();
/// let (passphrase, entropy) = generator.gen_from_pattern("w-w-w-w-dd-ss");
/// println!("Generated passphrase: {}", passphrase); //e.g. contense-backside-creamed-sterous-06-"?
/// println!("Entropy: {:.2} bits", entropy); // e.g. 69.23
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
/// let (password, entropy) = generator.gen_from_pattern("w.w.w.w");
/// println!("Custom passphrase: {}", password);
/// ```
pub struct Generator {
    pub rng: ChaCha8Rng,
    jump_table: HashMap<String, Distribution>,
    depth: usize,
    toks_per_word: f64,
}
impl Default for Generator {
    fn default() -> Self {
        Self::new()
    }
}

/// It holds the token frequency data, entropy values, and
/// other metadata necessary to create randomized sequences based on a Markov-like
/// transition model.
struct Distribution {
    tokens: Vec<String>,
    entropies: Vec<f64>,
    counts: Vec<usize>,
    total: usize,
}

impl Generator {
    /// Creates a new generator with a custom token set and a specified Markov chain depth.
    ///
    /// * `tokens`: A vector of words or tokens to use for password generation.
    /// * `chain_depth`: The depth of the Markov chain (how many preceding tokens are considered for generating the next token).
    pub fn new_custom(tokens: Vec<String>, chain_depth: usize) -> Generator {
        let rng = ChaCha8Rng::from_entropy();
        let (jump_table, toks_per_word) = Generator::distill(tokens, chain_depth);

        Generator {
            rng,
            jump_table,
            depth: chain_depth,
            toks_per_word,
        }
    }

    /// Creates a new generator using the default wordlist (EFF's word list) with a Markov chain depth of 3.
    pub fn new() -> Generator {
        Generator::new_custom(word_list::eff::list(), 3)
    }

    /// Similar to `new()`, but uses a Markov chain depth of 2 for quicker password generation at the expense of phonetic fidelity.
    pub fn new_he() -> Generator {
        Generator::new_custom(word_list::eff::list(), 2)
    }

    /// Generates a password based on a given pattern, while calculating its entropy.
    ///
    /// The pattern string defines how the password is structured, where different
    /// characters in the pattern correspond to different token types:
    ///
    /// * `'s'` - Inserts a symbol from the predefined symbol set (`@#!$%&=?^+-*"`).
    /// * `'d'` - Inserts a digit from the set `0-9`.
    /// * `'c'` - Generates a token using the markov chain.
    /// * `'C'` - Generates a token, capitalized.
    /// * `'w'` - Generates a word using the markov chain.
    /// * `'W'` - Generates a word, capitalized.
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
    /// In this example, the pattern `"wWsdC"` would generate a password such as `"hunkindEreso2"Mus"`,
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
                    if let Some(cn) = iter.next() {
                        passphrase.push(cn);
                    }
                    continue;
                }
                match c {
                    'w' | 'W' => {
                        for i in 1..=(self.toks_per_word.ceil() as usize) {
                            let (mut tok, h) = self.gen_next_token(&passphrase);
                            if c == 'W' && i == 1 {
                                tok = uppercase_first_letter(&tok);
                            }
                            passphrase.push_str(&tok);
                            entropy += h;
                        }
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
                        let (mut tok, h) = self.gen_next_token(&passphrase);
                        if c == 'C' {
                            tok = uppercase_first_letter(&tok);
                        }
                        passphrase.push_str(&tok);
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
        let mut tok = seed;
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
                panic!("unexpected");
            }
            if tok.len() == 0 {
                return ("".to_string(), 0.0);
            }
            tok = &tok[1..];
        }
    }

    fn distill(tokens: Vec<String>, depth: usize) -> (HashMap<String, Distribution>, f64) {
        let mut transition_matrix: HashMap<String, HashMap<String, usize>> = HashMap::new();

        let mut put = |str: String, r: String| {
            transition_matrix
                .entry(str)
                .or_default()
                .entry(r)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        };
        let mut tot_word_len = 0.0;
        let mut tot_tok_len = 0.0;

        for raw_w in tokens.iter() {
            let sl = raw_w.trim().to_lowercase();
            if sl.len() == 0 {
                continue;
            }
            let max_depth = depth.min(sl.len());
            tot_tok_len += max_depth as f64;
            tot_word_len += sl.len() as f64;
            for d in 1..=max_depth {
                let chars: Vec<String> = sl
                    .chars()
                    .collect::<Vec<char>>()
                    .chunks(d)
                    .map(|c| c.iter().collect::<String>())
                    .collect();

                for i in 0..chars.len().saturating_sub(1) {
                    put(chars[i].clone(), chars[i + 1].clone());
                }
                // this must only happen at the final depth, in order to bootstrap each word with the longest token
                if d == max_depth {
                    put("".to_string(), chars[0].clone());
                }
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

        (dist_trans_matrix, tot_word_len / tot_tok_len)
    }
}

fn uppercase_first_letter(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use word_list::simple;

    use super::*;

    fn certify(pattern: &str) -> bool {
        let mut gen = Generator::new_custom(simple::list(), 2);
        gen.rng = ChaCha8Rng::seed_from_u64(0x5792CBF); //fix seed for reproducible results
        let mut hist = HashMap::<String, usize>::new();
        let mut tot_h: f64 = 0.0;
        let mut tot_c: f64 = 1e-16;
        let mut q = 128;
        let mut old_entropy = 0.0;
        println!("testing pattern {}", pattern);
        loop {
            for _ in 0..q {
                let (pw, h) = gen.gen_from_pattern(pattern);
                tot_h += h;
                tot_c += 1.0;
                let v = hist.get(&pw).or(Some(&0)).unwrap();
                hist.insert(pw, v + 1);
            }
            q += q / 16;
            let avg_h = tot_h / tot_c;
            let mut entropy = 0.0 as f64;
            for (_, &v) in hist.iter() {
                let p = v as f64 / tot_c;
                entropy += -p * p.log2();
            }
            entropy += (hist.len() as f64 - 1.0) / (2.0 * tot_c);
            if (entropy - avg_h).abs() < 1e-2 {
                println!("- PASSED! unique words {}", hist.len());
                return true;
            }
            if (entropy - old_entropy).abs() < 1e-5 {
                println!("- WARNING, entropies {} {}.", entropy, avg_h);
                if (entropy - old_entropy).abs() < 1e-6 {
                    println!("- FAILED, entropies {} {}.", entropy, avg_h);
                    return false;
                }
            }
            old_entropy = entropy;
        }
    }

    #[test]
    fn test_word() {
        assert!(certify(""));
        assert!(certify("d"));
        assert!(certify("s"));
        assert!(certify("c"));
        assert!(certify("cc"));
        assert!(certify("w"));
        assert!(certify("ww"));
        assert!(certify("w.w"));
        assert!(certify("c.c"));
        assert!(certify("ccc"));
        assert!(certify("sdc"));
        assert!(certify("literal"));
    }
}
