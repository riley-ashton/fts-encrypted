# fts-encrypted

- embedded, on-disk, client side searching with symmetric encryption (AES-128)
- basic fts search: OR, AND
- text tokens and document ids are encrypted
- provides a default latin language tokenizer

Note: *token* refers to *lexical token*, not *cryptographic token*.
For example, a tokenizer may turn 'learns', 'learning', 'learned' all into the token 'learn'.

If you do not need encryption, [Tantivy](https://github.com/quickwit-oss/tantivy) is better in every way.

## Design
- a mapping of encrypted documents ids to a counter id is created (a unique 32bit number from an incremental counter)
- indexing using a record level [inverted index](https://en.wikipedia.org/wiki/Inverted_index),
  stores a mapping of encrypted hashes of tokens to sorted and bitpacked counter ids
- [sled](https://github.com/spacejam/sled) is used as the key-value store

## Demo

A basic GUI demo using dioxus and the enron email set [is available on my github here](https://github.com/riley-ashton/fts-encrypted-gui-demo).
It is primarily to show that search speed is decent for the kind
of datasets seen stored on client side applications.

## Security Warning

This is still a work in progress. No guarantees about this library or its dependencies, in implementation, conceptually or otherwise, are being made. No security audits have ever been performed. Use at your own risk.

## Lexical (keyword) token encryption
Each keyword in a search or index is tokenized.
This token and the table name it occurs in, are hashed with blake2b-128 
and then encrypted with AES-128-ECB before being stored or used for queries.

```ignorelang
Encrypt(Hash(token + table_name))
```

ECB mode is used for encryption. 
ECB causes identical plaintext to become identical, 
but this is not a concern for unique values like the hash of a token and table name.
This means the same token will have a different ciphertext if it occurs
in separate tables.

## Document Id Encryption

A document id is encrypted with AES-128-ECB. 
This is then associated with a 32-bit counter.

## Document Id Compression

Since a document id appears many times and the 
number of document ids is far smaller than can be enumerated with
128-bits, the document ids can be compressed.

### 32bit encodings

Assuming 1,000 unique tokens / document, 
the cost to store the occurrences of a token in the documents are:

| Documents | Unoptimized | 32bit      |
|-----------|-------------|------------|
| 1000      | 16MB        | 4MB        |
| 10k       | 160MB       | 40MB       |
| 50k       | 800MB       | 200MB      |
| 100k      | 1.6GB       | 400MB      |
| 250k      | 4GB         | 1GB        |
| million   | 16GB        | 4GB        |
| billion   | 16TB        | 4TB        |

### Differencing and Bitpacking

Differencing is representing values in a sequence as the difference
between them. This creates values that can be represented with fewer bits,
which allows tighter bitpacking.

The [bitpacking crate](https://lib.rs/crates/bitpacking) is used for
differencing and bitpacking blocks of 128 integers.

#### Amortized Bitpacking

Differencing works best when values are sorted, but maintaining sorted and bitpacked values would require re-encoding all the values when an out of order entry is added. Using a amortized approach with a collection of out of order values can reduce the cost of changes by amortizing them.

| Layer number | Packing scheme         | Sorting          | Diffing |
|--------------|------------------------|------------------|---------|
|      0       | None - 32bit (<128 ints)| None            | No      |    
|      1+      | BitPacker4x (128 ints) | Globally amoung layers above 0 | Yes |

### Example

Roughly 9,000-10,000 shorter Enron emails were compressed and the resulting fts db size was 235MB using 32-bit encoding. Using the amortized differencing and layered bitpacking changed that to 21MB.

### Tombstones

Deleting a file is...costly...amortization TODO

## In memory write buffering

TODO explore. Something like RocksDb memtable or sled.
Store changes in memory, then flush every 500ms or when memory limit is reached.

## Content aware autocompletion

Bucket sort words by first 3 or 4 characters (not tokenized), compress? and encrypt. 
Block encrypt with something with diffusion like CBC or GCM (authenicated encryption).
This would mean autocomplete would kick in after 3 or 4 characters.
*This is still in the conceptual stage.*

## Limitations

### Requirements
- the number of occurrences of the encrypted and hashed lexical token is not hidden;
  [frequency attacks](https://en.wikipedia.org/wiki/Frequency_analysis) must be mitigated
- protection against [known-plaintext attacks](https://en.wikipedia.org/wiki/Known-plaintext_attack)
  **are** required to avoid frequency-based attacks
- protection against [chosen-plaintext attacks](https://en.wikipedia.org/wiki/Chosen-plaintext_attack),
  and
  [padding oracle attacks](https://en.wikipedia.org/wiki/Padding_oracle_attack) **are not** required,
  since the client provides the key and the plaintext
- protection against [chosen-ciphertext attacks](https://en.wikipedia.org/wiki/Chosen-ciphertext_attack)
  is desired since an attacker could modify the index files.

#### Integrity Attacks
Data integrity is optional by hashing the database file at close time and storing an encrypted
version of the hash.


### Algorithms

#### AES-128 ECB
- provided by crate: [aes](https://docs.rs/aes/latest/aes/)
- no initialization vector
- vulnerable to chosen plaintext and ciphertext attacks, but that is out of scope
- identical plaintext blocks are encrypted as identical ciphertext blocks
- since the same token value can occur in two separate tables, table name is appended to the token before hashing
- used for encoding hashed table name + token values, as table name + token values are unique
- since the cleartext being encoded are guaranteed to be unique, the dangers of this algorithm do not apply
- AES-256 support may be added (the block size is still the same at 128 bits, only the key size changes to 256 bits)

### BLAKE2
- provided by crate: [blake2](https://docs.rs/blake2/latest/blake2/)
- cryptographic hash function with chosen output length
- good enough collision resistance for tokens


### Shortcomings

There is no diffusion on encrypted document ids.
Adding diffusion would require encrypting document ids using a randomly generated IV.
This would also make compression impossible.
Storing the IV would add 128-bits per token and document pair (for AES CBC).

The following is visible to an attacker without a key:

- number of tokens (but not the length of the token)
- number of tokens in a document (but not which document)
- number of documents in the index
- whether two documents share the same token (but not the id of either document)

In the case of an index on a patient list at a doctor's office, an attacker
without a key could see the number of patients and a distribution of tokens
used within documents. They could not see any plaintext, such as names
or other identifiers, and they could not even see the document id of any patients.
They could see if two patients share a search token, but nothing about whom the
patients or what the shared information is.

For example if the search index was
only built on names in a country with common last names, such as Vietnam,
you could do a frequency analysis and figure out the likely number of patients
with the last name Nguyen (38% of Vietnam's population).
This relies on your prior (distribution of surnames) being valid for the
dataset at hand. It would also only be effective against common names, which is
not identifying and would be unlikely to confidently distinguish documents containing
even the second from the third most common surname in Vietnam (Tran at 11% and Le at 10%).

Once more information
is added into the search index, such as age, hometown, address, description, etc.,
the ability to conduct frequency analysis virtually disappears.

### Non-repudiation limitations

One concern may be non-repudiation of storing unique datasets, where a frequency analysis
of a large known plaintext data set could be used to show that beyond a reasonable doubt,
a given device had that data set indexed.
This would seemingly only affect dissidents in authoritarian countries or criminals.
This can be mitigated by full disk encryption when the device is off.

### Effects of token hash collision

Let `d1` be a document with a token `t1`. Let `t2` be a token whose hash collides with `t1` and is not
a token of the document `d1`.

False positives, where additional unrelated results were included in a search result, can occur to `d1`
if the search contains `t2` and not `t1`.

False negatives, where relevant results were omitted from a search result, can only occur if one of the
colliding tokens was deleted for a document. This would result in the other token being "deleted" as well.

False positives or negatives only apply to documents that have one of the colliding tokens,
when the other colliding token is present in the search query. This makes the stakes of such a collision
very low.

The actual risk of a collision is comically small for 128bit hashes (see birthday problem on wikipedia).

## Performance Priorities
- be fast enough to not negatively impact user performance (10ms-100ms a search is fine)
- storage performance is a main priority

## Out of scope
- word-level inverted index or advanced fts search like [phrase searches](https://en.wikipedia.org/wiki/Phrase_search)
- authenticated encryption
- removing all tokens corresponding to a document, without knowing what those tokens are 
- fuzzy searching

## Future Work
- user provided alternate tokenizers
- optional integrity checks at startup and closing
- in memory write buffer?
- options in backend, or make it user pluggable (RocksDB, LMDB come to mind)
- AES-256? (256bit key, but still keeps 128bit block size = no increase in space required)
- better benchmarks?
- content aware autocompletion?

### Why not 64-bit hashing and encryption?

64 bit encryption only results in a few megabytes of space savings for very large indexes.
English has about 1,000,000 words and fewer tokens. 64 million bits is only 8MB.
Given the power law type distributions seen in languages, 
where the top hundred or so words can comprise half the frequency,
the actual savings would be considerably less.
