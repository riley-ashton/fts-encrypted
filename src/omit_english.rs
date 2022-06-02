use rust_stemmers::{Algorithm, Stemmer};
use std::collections::HashSet;

/// A default list of english words to omit from full text searches.
/// Taken from the most common english words, whose inclusion
/// would generally not add much to searches.
pub(crate) fn default_english_omit_words() -> HashSet<String> {
    let stemmer = Stemmer::create(Algorithm::English);

    vec![
        // the following words are the 100 most frequent english words
        "the",
        "of",
        "and",
        "in",
        "a",
        "to",
        "was",
        "is",
        "for",
        "as",
        "on",
        "with",
        "by",
        "that",
        "he",
        "from",
        "his",
        "at",
        "it",
        "an",
        "are",
        "were",
        "which",
        "this",
        "or",
        "be",
        "also",
        "has",
        "had",
        "one",
        //"first",
        "their",
        "not",
        "but",
        "its",
        "have",
        "new",
        "they",
        "who",
        "after",
        "other",
        "her",
        "been",
        "two",
        "when",
        "there",
        "she",
        "all",
        "into",
        "more",
        "during",
        "time",
        "most",
        //"years",
        "some",
        "only",
        "over",
        "many",
        "s",
        "can",
        "such",
        //"used",
        "would",
        //"school",
        //"city",
        "may",
        "up",
        "out",
        "him",
        "where",
        "later",
        "these",
        "between",
        "about",
        "under",
        //"world",
        "then",
        "known",
        "than",
        "made",
        "however",
        //"united",
        "no",
        "while",
        //"state",
        //"states",
        //"three",
        //"part",
        "being",
        "became",
        //"year",
        "both",
        "them",
        "through",
        "including",
        //"war",
        //"name",
        //"area",
        //"well",
        //"national",
        //
        // The following are selected words from the
        // 100-200 most frequent english words
        "i",    // 103
        "now",  // 124
        "so",   // 125
        "use",  // 126
        "if",   // 131
        "each", //132
        "any",  // 137
        //
        // The following are added words
        "you",
        "do",
    ]
    .into_iter()
    .map(|x| stemmer.stem(x).to_string())
    .collect()
}
