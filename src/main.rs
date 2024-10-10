use cryptirust::*;

pub fn main() {
    // Initialize a new Generator instance
    let pattern = std::env::args().nth(1).unwrap_or("w-c-s-d".to_string());
    let num = std::env::args()
        .nth(2)
        .unwrap_or("5".to_string())
        .parse::<u64>()
        .unwrap_or(5);
    let depth = std::env::args()
        .nth(3)
        .unwrap_or("3".to_string())
        .parse::<usize>()
        .unwrap_or(3);
    let mut generator = Generator::new_custom(word_list::eff::list(), depth);
    // Generate a passphrase with 5 words
    println!(
        "{:10}    {:15}    {}",
        "        n.", " log2(guesses)", "secret"
    );
    for i in 0..num {
        let (passphrase, pass_entropy) = generator.gen_from_pattern(&pattern);
        println!(
            "{:10}    {:15.2}    {}",
            i + 1,
            pass_entropy - 1.0,
            passphrase
        );
    }
}
