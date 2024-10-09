use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
pub mod word_list;
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
        let mut wordvec = Vec::new();
        let mut total_entropy = 0.0;
        for _ in 0..words {
            let (tok, entropy) = self.gen_from_pattern("w");
            wordvec.push(tok);
            total_entropy += entropy;
        }
        (wordvec.join("."), total_entropy)
    }

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
                        let (mut head, h_head) = self.gen_next_token("");
                        let (leng, h_leng) = self.gen_word_length();
                        if c == 'W' {
                            head = head.to_uppercase();
                        }
                        while head.len() < leng {
                            let (nc, nh) = self.gen_next_token(&head.to_lowercase());
                            head.push_str(&nc);
                            entropy += nh;
                        }
                        passphrase.push_str(&head);
                        if iter.peek().unwrap_or(&'0') == &'w' {
                            passphrase.push('.');
                        }
                        entropy += h_head + h_leng;
                    }
                    'd' => {
                        let d = self.rng.gen_range(0..10);
                        let h = (10f64).log2();
                        passphrase.push_str(&d.to_string());
                        entropy += h;
                    }
                    's' => {
                        let symbols = "@#!$%&=?^+-*\"";
                        let d = self.rng.gen_range(0..symbols.len());
                        let h = (symbols.len() as f64).log2();
                        passphrase.push(symbols.chars().nth(d).unwrap());
                        entropy += h;
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
