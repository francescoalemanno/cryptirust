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
//! - **CLI**: most functions of cryptirust are easily accessible from [Crypticli](`crypticli::cli`).
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
//!     let mut generator = Generator::new_custom(word_list::eff::list(), 2).unwrap();
//!     let (passphrase, entropy) = generator.gen_from_pattern("w.w.w.w");;
//!     println!("Generated passphrase: {}", passphrase);
//!     println!("Entropy: {:.2} bits", entropy);
//! }
//! ```
//!
//! ## License
//!
//! Cryptirust is licensed under the MIT License.
//!
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
pub mod crypticli;
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
/// let mut generator = Generator::new_custom(custom_tokens, 2).unwrap();
/// let (password, entropy) = generator.gen_from_pattern("w.w.w.w");
/// println!("Custom passphrase: {}", password);
/// ```
pub struct Generator {
    pub rng: ChaCha8Rng,
    depth: usize,
    jump_table: HashMap<String, Distribution>,
}
impl Default for Generator {
    fn default() -> Self {
        Self::new()
    }
}

/// It holds the token frequency data, entropy values, and
/// other metadata necessary to create randomized sequences based on a Markov-like
/// transition model.
#[derive(Debug)]
struct Distribution {
    tokens: Vec<String>,
    entropies: Vec<f64>,
    counts: Vec<usize>,
    total: usize,
}

impl Generator {
    /// Creates a new generator with a custom token set and a specified Markov chain depth.
    pub fn new_custom(tokens: Vec<String>, depth: usize) -> Option<Generator> {
        let depth = depth.max(1);
        let rng = ChaCha8Rng::from_entropy();
        let transition_matrix = transition_matrix_from_tokens(tokens, depth);
        if transition_matrix.len() == 0 {
            return None;
        }
        let jump_table = jump_table_from_transition_matrix(transition_matrix);
        if jump_table.len() == 0 {
            return None;
        }
        Some(Generator {
            rng: rng,
            depth: max_depth(&jump_table),
            jump_table: jump_table,
        })
    }

    /// Creates a new generator using the default wordlist (EFF's word list) with a Markov chain depth of 3.
    pub fn new() -> Generator {
        Generator::new_custom(word_list::eff::list(), 3).unwrap()
    }

    /// Similar to `new()`, but uses a Markov chain depth of 2 for quicker password generation at the expense of phonetic fidelity.
    pub fn new_he() -> Generator {
        Generator::new_custom(word_list::eff::list(), 2).unwrap()
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
                        let mut nlen = 0;
                        while nlen < 8 {
                            let (mut tok, h) = self.gen_next_token(&passphrase).unwrap();
                            if c == 'W' && nlen == 0 {
                                tok = uppercase_first_letter(&tok);
                            }
                            passphrase.push_str(&tok);
                            entropy += h;
                            nlen += self.depth;
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
                        let (mut tok, h) = self.gen_next_token(&passphrase).unwrap();
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
    /// # Example
    ///
    /// ```rust
    /// # use cryptirust::Generator;
    /// let mut generator = Generator::new();
    /// let (token, entropy) = generator.gen_next_token("he").unwrap();
    /// println!("Next token: {}, Entropy: {}", token, entropy);
    /// ```
    ///
    /// This example demonstrates how to generate the next token in a sequence starting with
    /// the seed `"he"`. The method returns both the token and its associated entropy.
    pub fn gen_next_token(&mut self, seed: &str) -> Option<(String, f64)> {
        let sl = seed[seed.len().saturating_sub(self.depth)..].to_lowercase();
        let mut tok = sl.as_str();
        loop {
            if let Some(tr) = self.jump_table.get(tok) {
                let n = self.rng.gen_range(0..tr.total);
                for (i, v) in tr.counts.iter().enumerate() {
                    if n < *v {
                        return Some((tr.tokens[i].clone(), tr.entropies[i]));
                    }
                }
                return None;
            }
            if tok.len() == 0 {
                return None;
            }
            tok = &tok[1..];
        }
    }
}

fn max_depth(jump_table: &HashMap<String, Distribution>) -> usize {
    let mut t_depth = 0;
    for (k, v) in jump_table.iter() {
        t_depth = t_depth.max(k.len());
        for c in v.tokens.iter() {
            t_depth = t_depth.max(c.len());
        }
    }
    t_depth
}

fn transition_matrix_from_tokens(
    tokens: Vec<String>,
    depth: usize,
) -> HashMap<String, HashMap<String, usize>> {
    let mut transition_matrix: HashMap<String, HashMap<String, usize>> = HashMap::new();

    let mut put = |str: String, r: String| {
        transition_matrix
            .entry(str)
            .or_default()
            .entry(r)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    };

    for raw_w in tokens.iter() {
        let sl = raw_w.trim().to_lowercase();
        if sl.len() == 0 {
            continue;
        }
        let sb: Vec<char> = sl.chars().collect::<Vec<char>>();
        for i in 0..sb.len() {
            let from = sb[i.saturating_sub(depth)..i].into_iter().collect();
            let to = sb[i..(i + depth).min(sb.len())].into_iter().collect();
            if to == "" || from == to {
                continue;
            }
            put(from, to);
        }
    }
    transition_matrix
}

fn jump_table_from_transition_matrix(
    transition_matrix: HashMap<String, HashMap<String, usize>>,
) -> HashMap<String, Distribution> {
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

fn uppercase_first_letter(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use word_list::debug;

    use super::*;

    fn certify(pattern: &str) -> bool {
        let mut gen = Generator::new_custom(debug::list(), 2).unwrap();
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
