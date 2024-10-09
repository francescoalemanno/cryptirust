use cryptirust::*;

fn main() {
    // Initialize a new Generator instance
    let mut generator = Generator::new();
    let mut h: f64 = 0.0;
    let mut cnt: f64 = 0.0;
    // Generate a passphrase with 5 words
    for i in 0..100000 {
        let (passphrase, pass_entropy) = generator.gen_from_pattern("Jccccccc");
        h += pass_entropy;
        cnt += 1.0;
        println!("{} {} {} {}", i, passphrase, pass_entropy, h / cnt);
    }
    // Generate a consonant-vowel word with 3 CV pairs
    let (cv_word, cv_entropy) = generator.gen_cv_word(30);
    println!("Generated CV Word: {}", cv_word);
    println!("CV Word Entropy: {} bits", cv_entropy);
}
