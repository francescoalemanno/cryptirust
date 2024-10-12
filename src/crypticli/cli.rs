//! Flexible password generator based on the [Cryptirust](`crate`) library.
//!
//! # Installation
//! ```bash
//! > cargo install cryptirust
//! ```
//!
//! # Usage
//! ```bash
//! > crypticli --help
//! ```
//! outputs
//! ```bash
//!   Usage: crypticli [-p <pattern>] [-n <num>] [-d <depth>]
//!   
//!   Flexible password generator based on the Cryptirust library.
//!   
//!   Options:
//!     -p, --pattern     string representing the desired structure of the generated
//!                       passphrases, default is `w-c-s-d` (word-token-symbol-digit).
//!     -n, --num         number of passphrases to generate, must be a positive
//!                       integer.
//!     -d, --depth       depth of the markov model, 1...3 are reasonable values.
//!
//!     --help            display usage information
//! ```
//!
//! # Example
//! ```bash
//! > crypticli -p w.w.w.w-20dd -n 10
//! ```
//! output:
//! ```bash
//!       n.     log2(guesses)     secret
//!       1              67.87    glarean.seventail.judgines.passion-2049
//!       2              69.71    baskettle.frustrep.banjohn.captivate-2036
//!       3              71.35    pephant.matee.prodigan.patious-2088
//!       4              65.86    smokedgi.extroving.banknote.juggling-2068
//!       5              64.37    travesty.vetor.trifled.calmana-2002
//!       6              66.85    showering.visorne.sprinked.delirical-2009
//!       7              62.35    ranked.neglected.removing.requished-2024
//!       8              71.86    landmine.nextinc.itablemis.droola-2004
//!       9              59.82    mumbone.stoics.twitter.crawling-2014
//!       10             65.83    dumpster.waferris.liability.unabaster-2098
//!```
//!
//! # License
//!
//! Cryptirust is licensed under the MIT License.
//!
use crate::word_list::*;
use crate::Generator;
use argh::*;
enum WordList {
    English(),
    Italian(),
    CV(),
}

impl FromArgValue for WordList {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        match value {
            "italian" => Ok(WordList::Italian()),
            "eff" => Ok(WordList::English()),
            "cv" => Ok(WordList::CV()),
            _ => Err("non existant word list, use one of [italian, cv, eff].".to_string()),
        }
    }
}

#[derive(FromArgs)]
/// Flexible password generator based on the Cryptirust library.
struct Cli {
    /// string representing the desired structure of the generated passphrases, default is `w-c-s-d` (word-token-symbol-digit).
    #[argh(option, short = 'p', default = "String::from(\"w-c-s-d\")")]
    pattern: String,

    /// number of passphrases to generate, must be a positive integer.
    #[argh(option, short = 'n', default = "5")]
    num: usize,

    /// depth of the markov model, 1...3 are reasonable values.
    #[argh(option, short = 'd', default = "3")]
    depth: usize,

    /// word style: eff (english), italian, or cv (consonant-vowel pairs)
    #[argh(option, short = 's', default = "WordList::English()")]
    style: WordList,
}

pub fn cli_main() {
    let args: Cli = argh::from_env();
    let mut generator = Generator::new_custom(
        match args.style {
            WordList::English() => eff::list(),
            WordList::Italian() => italian::list(),
            WordList::CV() => cv::list(),
        },
        args.depth,
    )
    .unwrap();
    // Generate a passphrase with 5 words
    println!(
        "{:10}    {:15}    {}",
        "        n.", " log2(guesses)", "secret"
    );
    for i in 0..args.num {
        let (passphrase, pass_entropy) = generator.gen_from_pattern(&args.pattern);
        println!(
            "{:10}    {:15.2}    {}",
            i + 1,
            pass_entropy - 1.0,
            passphrase
        );
    }
}
