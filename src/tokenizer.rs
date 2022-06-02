use rust_stemmers::Stemmer;
use std::collections::HashSet;
use std::iter::Peekable;
use std::str::Chars;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Token(String);

/// Creates a set of tokens from a given string.
///
/// The `to_omit` set should be stemmed.
///
/// This is done by:
/// 1. converting to string to lowercase
/// 2. replacing whitespace and punctuation with space, excluding apostrophe
/// 3. omitting non-alphanumeric characters
/// 4. splitting at whitespace
/// 5. filtering apostrophes at beginning or end of words
/// 6. replacing contractions
/// 7. stemming the words using the provided `stemmer`
/// 8. filtering words in the list `to_omit`
pub(crate) fn tokenize(x: String, stemmer: &Stemmer, to_omit: &HashSet<String>) -> HashSet<Token> {
    let lowercase = LowerCaseString::from(x);
    let cleaned = lowercase.clean();
    let split = cleaned.split();
    let apostrophe_removed = split.remove_apostrophe_forms();
    let stemmed = apostrophe_removed.stem(stemmer);
    stemmed.filter(to_omit)
}

impl Token {
    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

/// A lower case string.
struct LowerCaseString(String);

/// A string that has been cleaned and is ready to
/// be split
struct CleanedString(String);

/// A string that has been cleaned and split by whitespace
struct SplitString(Vec<String>);

/// Words that have their apostrophe forms replaced or removed
struct ApostropheReplaced(Vec<String>);

/// Strings that have been cleaned, split by whitespace and
/// have specific words omitted
struct StemmedWords(Vec<String>);

impl LowerCaseString {
    fn from(x: String) -> LowerCaseString {
        LowerCaseString(x.to_lowercase())
    }

    /// Cleans a lowercase string for splitting
    /// Keeps alphanumerics and apostrophes,
    /// replaces whitespace and punctuation with space,
    /// and omits everything else
    fn clean(self) -> CleanedString {
        let chars = self.0.chars();

        let string = chars
            .into_iter()
            .filter_map(|c| {
                if c.is_alphanumeric() {
                    return Some(c);
                }
                if c == '\'' {
                    return Some('\'');
                }
                if c.is_ascii_punctuation() {
                    return Some(' ');
                }
                if c.is_whitespace() {
                    return Some(' ');
                }
                None
            })
            .collect();

        CleanedString(string)
    }
}

impl CleanedString {
    /// split a CleanedString by its whitespace
    fn split(self) -> SplitString {
        let strings = self
            .0
            .split_whitespace()
            .into_iter()
            .map(|x| x.to_string())
            .collect();
        SplitString(strings)
    }
}

impl SplitString {
    /// '{} => {}
    /// {}' => {}
    /// {}'s => {}
    /// {}n't => {} + not
    /// {}'ve => {} + have
    /// {}'ll => {} + will
    /// {}'d => {} + had
    /// TODO replace_apostrophe_forms and add option

    /// Remove the apostrophe forms,
    /// since the endings are often in omitted lists anyways.
    ///
    /// '{} | {}' | {}'s | {}n't | {}'ve | {}'ll | {}'d => {}
    fn remove_apostrophe_forms(self) -> ApostropheReplaced {
        let removed = self
            .0
            .into_iter()
            .map(|mut x| {
                let apostrophe_present = x.contains('\'');

                if apostrophe_present {
                    x = Self::remove_contractions(x);
                    let chars = x.chars().peekable();
                    let chars = Self::remove_trailing_apostrophe(chars);
                    let chars = Self::remove_leading_apostrophe(chars);
                    x = chars.collect()
                }
                x
            })
            .collect();
        ApostropheReplaced(removed)
    }

    fn remove_contractions(x: String) -> String {
        x.replace("'s", "")
            .replace("n't", "")
            .replace("'ve", "")
            .replace("'ll", "")
            .replace("'d", "")
    }

    fn remove_trailing_apostrophe(mut chars: Peekable<Chars>) -> Peekable<Chars> {
        let trailing_apostrophe = chars.clone().last().map(|x| x == '\'').unwrap_or_default();

        if trailing_apostrophe {
            chars.next_back();
        }

        chars
    }

    fn remove_leading_apostrophe(mut chars: Peekable<Chars>) -> Peekable<Chars> {
        let leading_apostrophe = chars.peek() == Some(&'\'');

        if leading_apostrophe {
            chars.next();
        }

        chars
    }
}

impl ApostropheReplaced {
    /// Applies the stemmer to the strings,
    /// removing any duplicates
    fn stem(self, stemmer: &Stemmer) -> StemmedWords {
        let stemmed = self
            .0
            .into_iter()
            .map(|x| stemmer.stem(&x).to_string())
            .collect();
        StemmedWords(stemmed)
    }
}

impl StemmedWords {
    /// Filter out the stemmed words to omit
    fn filter(self, to_omit: &HashSet<String>) -> HashSet<Token> {
        self.0
            .into_iter()
            .filter(|x| !to_omit.contains(x))
            .map(Token)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::tokenizer::{tokenize, LowerCaseString, Token};
    use rust_stemmers::{Algorithm, Stemmer};
    use std::collections::HashSet;

    const TEXT: &str =
        "'If you tell the truth, you don't have to remember anything' - Mark Twain's quote";
    const CLEANED: &str =
        "'if you tell the truth  you don't have to remember anything'   mark twain's quote";

    fn split_text() -> Vec<String> {
        vec![
            "'if",
            "you",
            "tell",
            "the",
            "truth",
            "you",
            "don't",
            "have",
            "to",
            "remember",
            "anything'",
            "mark",
            "twain's",
            "quote",
        ]
        .into_iter()
        .map(|x| x.to_string())
        .collect()
    }

    fn apostrophe_removed_text() -> Vec<String> {
        vec![
            "if", "you", "tell", "the", "truth", "you", "do", "have", "to", "remember", "anything",
            "mark", "twain", "quote",
        ]
        .into_iter()
        .map(|x| x.to_string())
        .collect()
    }

    fn omit() -> HashSet<String> {
        vec!["the", "of", "if", "have", "t", "to", "you", "do"]
            .into_iter()
            .map(|x| x.to_string())
            .collect()
    }

    #[test]
    fn tokenizer_precursors() {
        let lowercase = LowerCaseString::from(TEXT.to_string());

        let cleaned = lowercase.clean();
        assert_eq!(CLEANED, cleaned.0.as_str());

        let split = cleaned.split();
        assert_eq!(&split_text(), &split.0);

        let apostrophe_removed = split.remove_apostrophe_forms();
        assert_eq!(&apostrophe_removed_text(), &apostrophe_removed.0);
    }

    #[test]
    fn tokenized() {
        let stemmer = Stemmer::create(Algorithm::English);
        let tokens = tokenize(TEXT.to_string(), &stemmer, &omit());
        let mut tokens: Vec<_> = tokens.into_iter().collect();
        tokens.sort();

        let expected = vec![
            Token("anyth".to_string()),
            Token("mark".to_string()),
            Token("quot".to_string()),
            Token("rememb".to_string()),
            Token("tell".to_string()),
            Token("truth".to_string()),
            Token("twain".to_string()),
        ];

        assert_eq!(expected, tokens);
    }
}
