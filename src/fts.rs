use rust_stemmers::{Algorithm, Stemmer};
use secrecy::Secret;
use std::cell::Cell;
use std::collections::HashSet;
use std::sync::Mutex;

use crate::bitpacking::{get_id_counters, update};
use crate::doc_id::{DocId, EncryptedDocId};
use crate::error::{Error, FtsResult};
use crate::omit_english::default_english_omit_words;
use crate::symmetric_key::SymmetricKey;
use crate::token_encryption::encrypt_token;
use crate::tokenizer::tokenize;

/// The full text search object
/// TODO description
pub struct Fts {
    /// &[u8; 16] (Token) -> &[u8; 4x] (codings)
    store: sled::Tree,
    /// &[u8; 16] (DocId encrypted) -> &[u8; 4] (coding)
    encoder: sled::Tree,
    /// &[u8; 4] (coding) -> &[u8; 16] (DocId encrypted)
    decoder: sled::Tree,
    stemmer: Stemmer,
    to_omit: HashSet<String>,
    key: Secret<SymmetricKey>,
    next: Mutex<Cell<u32>>,
}

fn next_id(decoder: &sled::Tree) -> u32 {
    if decoder.is_empty() {
        return 1;
    }

    let key = decoder.last().unwrap().unwrap().0;
    assert_eq!(key.len(), 4); // TODO remove assertion
    let mut bytes = [0u8; 4];

    for i in 0..4 {
        bytes[i] = key[i];
    }

    let mut counter = u32::from_le_bytes(bytes);
    counter += 1;
    counter
}

impl Fts {
    /// A Fts with default omit words and English stemmer
    pub fn new_default(db: &sled::Db, key: [u8; 16]) -> Self {
        Self::new(db, Algorithm::English, default_english_omit_words(), key)
    }

    /// A Fts with user specified language stemming algorithm and omit list.
    /// Note the omit list gets stemmed by the given stemmer.
    pub fn new(
        db: &sled::Db,
        language: Algorithm,
        to_omit: HashSet<String>,
        key: [u8; 16],
    ) -> Self {
        let stemmer = Stemmer::create(language);
        let key = Secret::new(SymmetricKey::from(key));
        let store = db.open_tree("store").unwrap();
        let encoder = db.open_tree("encoder").unwrap();
        let decoder = db.open_tree("decoder").unwrap();
        let next = Mutex::new(Cell::new(next_id(&decoder)));

        let to_omit = to_omit
            .into_iter()
            .map(|x| stemmer.stem(&x).to_string())
            .collect();

        Self {
            store,
            encoder,
            decoder,
            stemmer,
            to_omit,
            key,
            next,
        }
    }

    /// Add a document to the index
    pub fn add_document(&self, document: DocId, terms: String) -> FtsResult<()> {
        let item = document.encrypt(&self.key);
        let tokens = tokenize(terms, &self.stemmer, &self.to_omit);
        let doc_counter = self.get_encoding(item)?;
        let table_name = "default"; // TODO table namespacing

        let encrypted_tokens = tokens
            .into_iter()
            .map(|token| encrypt_token(token, table_name, &self.key));

        for token in encrypted_tokens {
            update(&self.store, doc_counter, token)?;
        }

        Ok(())
    }

    /// Get all the document ids for documents that contain
    /// all the given search tokens (important words) in the search `term`.
    pub fn search(&self, term: String) -> FtsResult<Vec<DocId>> {
        let tokens = tokenize(term, &self.stemmer, &self.to_omit);
        let mut tokens: Vec<_> = tokens.into_iter().collect();
        let table_name = "default"; // TODO table namespacing

        // NOTE: merging ids, since they are almost sorted, rather than using
        // a hashmap might be worth exploring

        let mut matches: HashSet<u32> = if let Some(token) = tokens.pop() {
            let token = encrypt_token(token, table_name, &self.key);
            let ids = get_id_counters(&self.store, token)?;
            ids.into_iter().collect()
        } else {
            return Ok(vec![]);
        };

        for token in tokens {
            let token = encrypt_token(token, table_name, &self.key);
            let ids = get_id_counters(&self.store, token)?;
            matches = ids.into_iter().filter(|x| matches.contains(x)).collect();
        }

        self.doc_counters_to_decrypted_ids(matches)
    }

    fn doc_counters_to_decrypted_ids(&self, counters: HashSet<u32>) -> FtsResult<Vec<DocId>> {
        counters
            .into_iter()
            .map(|counter| -> FtsResult<DocId> {
                let id_ivec = self
                    .decoder
                    .get(counter.to_le_bytes())?
                    .ok_or(Error::Decode)?;

                let encrypted_id: EncryptedDocId = id_ivec.try_into()?;
                let id = encrypted_id.decrypt(&self.key);
                Ok(id)
            })
            .into_iter()
            .collect()
    }

    /// Deletes the given term from the index.
    /// This is a fast operation, probably O(1) depending to the kv-store.
    pub fn delete_term(&self, _term: String) {
        todo!("Delete term is not yet implemented")
    }

    /// Deletes given terms from the document.
    ///
    /// This is a relatively expensive operation.
    /// For each term in the document, this requires scanning through potentially all the
    /// document ids that share the same term.
    pub fn delete_document(&self, _document: DocId, _terms: String) {
        todo!("Delete document is not yet implemented")
    }

    /// Deletes everything in the index and drops the struct.
    pub fn clear_all(self) -> sled::Result<()> {
        self.store.clear()
    }

    fn get_encoding(&self, document: EncryptedDocId) -> sled::Result<u32> {
        let ivec: sled::IVec = document.into();

        if let Some(encoding) = self.encoder.get(&ivec)? {
            let mut bytes = [0u8; 4];

            for i in 0..4 {
                bytes[i] = encoding[i];
            }

            Ok(u32::from_le_bytes(bytes))
        } else {
            let mut guard = self.next.lock().unwrap();
            let counter = guard.get();
            *guard.get_mut() += 1;
            let encoding = counter.to_le_bytes();
            self.encoder.insert(&ivec, &encoding[..])?;
            self.decoder.insert(&encoding[..], ivec)?;
            Ok(counter)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::symmetric_key::demo_key;

    use super::*;

    fn ping_pong_id() -> DocId {
        DocId::new([
            91, 121, 105, 218, 72, 12, 158, 255, 190, 145, 3, 107, 77, 42, 166, 103,
        ])
    }

    fn ping_pong_document() -> String {
        std::fs::read_to_string("./test_stories/ballade_of_ping_pong.txt").unwrap()
    }

    fn ballet_girl_id() -> DocId {
        DocId::new([
            155, 20, 204, 141, 171, 95, 47, 23, 208, 76, 28, 158, 66, 179, 120, 10,
        ])
    }

    fn ballet_girl_document() -> String {
        std::fs::read_to_string("./test_stories/ballet_girl.txt").unwrap()
    }

    fn boat_doc_id() -> DocId {
        DocId::new([
            144, 187, 247, 203, 181, 180, 88, 31, 244, 112, 21, 116, 198, 126, 58, 87,
        ])
    }

    fn boat_document() -> String {
        std::fs::read_to_string("./test_stories/boat_that_a_int.txt").unwrap()
    }

    #[test]
    fn fts_works() {
        let _ = std::fs::remove_dir_all("test.db");
        let db = sled::open("test.db").unwrap();
        let fts = Fts::new_default(&db, demo_key());

        fts.add_document(ping_pong_id(), ping_pong_document())
            .unwrap();
        fts.add_document(ballet_girl_id(), ballet_girl_document())
            .unwrap();
        fts.add_document(boat_doc_id(), boat_document()).unwrap();

        // Try a search
        let search_result = fts.search("boat".to_string()).unwrap();
        assert_eq!(1, search_result.len());
        assert_eq!(boat_doc_id(), search_result[0]);

        // Try another search
        let search_result = fts.search("ping pong".to_string()).unwrap();
        assert_eq!(1, search_result.len());
        assert_eq!(ping_pong_id(), search_result[0]);

        let _ = std::fs::remove_dir_all("test.db");
    }

    #[cfg(feature = "uuids")]
    #[test]
    fn fts_unique() {
        let _ = std::fs::remove_dir_all("growing_test.db");
        let db = sled::open("growing_test.db").unwrap();
        let fts = Fts::new_default(&db, demo_key());

        let unique_doc_1: DocId = uuid::Uuid::new_v4().into();
        fts.add_document(unique_doc_1.clone(), "unique".to_string())
            .unwrap();

        for _ in 0..500 {
            let document = uuid::Uuid::new_v4().into();
            fts.add_document(document, "dummy".to_string()).unwrap();
        }

        let unique_doc_2: DocId = uuid::Uuid::new_v4().into();
        fts.add_document(unique_doc_2.clone(), "unique".to_string())
            .unwrap();

        let unique_result = fts.search("unique".to_string()).unwrap();
        assert_eq!(2, unique_result.len());
        assert!(unique_result.contains(&unique_doc_2));
        assert!(unique_result.contains(&unique_doc_1));

        let _ = std::fs::remove_dir_all("growing_test.db");
    }
}
