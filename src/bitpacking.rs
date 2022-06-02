use std::collections::BinaryHeap;

use bitpacking::{BitPacker, BitPacker4x};

use crate::token_encryption::EncryptedToken;

/// Values must be sorted
pub(crate) fn pack_128(token: &[u8], values: &[u32]) -> (Vec<u8>, Vec<u8>) {
    let initial = values[0];
    let bitpacker = BitPacker4x::new();
    let num_bits = bitpacker.num_bits_sorted(initial, values);
    let mut compressed = vec![0u8; 4 * BitPacker4x::BLOCK_LEN];

    let byte_count = bitpacker.compress_sorted(initial, values, &mut compressed[..], num_bits);
    compressed.truncate(byte_count);

    let key = encode(token, initial, num_bits);
    (key, compressed)
}

// Tombstones at TOKEN[0:16] + MAX_U32[0:4] ([255, 255, 255, 255])
// Up to 255 tombstones, then re-encoding occurs

// Raw 32 bit counters at TOKEN[0:16] + [X; 4] expect [0,0,0,0] or [255,255,255,255]

// TOKEN [0..16] + INITIAL [16..20] + NUM_BITS[20..21]
// 21 bytes overhead per 256 integers
// INITIAL of zero is reserved for unsorted, unpacked values (<255 or 1020 bytes)
// Little endian encoded intial and bitcount
fn encode(token: &[u8], initial: u32, num_bits: u8) -> Vec<u8> {
    let mut encoding = token.to_vec();

    for byte in initial.to_le_bytes() {
        encoding.push(byte);
    }

    encoding.push(num_bits);
    encoding
}

pub(crate) fn unpack_128(key: &[u8], values: &[u8]) -> Vec<u32> {
    let initial = initial_from_key(key);
    let num_bits = num_bits_from_key(key);
    let bitpacker = BitPacker4x::new();
    let mut decompressed = vec![0u32; BitPacker4x::BLOCK_LEN];
    bitpacker.decompress_sorted(initial, values, &mut decompressed, num_bits);
    decompressed
}

pub(crate) fn update(tree: &sled::Tree, doc: u32, token: EncryptedToken) -> sled::Result<()> {
    let token = token.into_vec();

    if contains_doc_token_pair(tree, doc, &token)? {
        return Ok(());
    }

    let (previous, resize_needed) = update_unsorted(tree, &token, doc)?;

    if resize_needed {
        if let Some(previous) = previous {
            update_bitpacked(tree, &token, &previous)?;
        }
    }

    Ok(())
}

/// Get the counter values corresponding to the document ids
/// associated with the given token.
pub(crate) fn get_id_counters(tree: &sled::Tree, token: EncryptedToken) -> sled::Result<Vec<u32>> {
    let mut ids = vec![];

    for result in tree.scan_prefix(token) {
        let (key, values) = result?;

        if is_unpacked_key(&key) {
            let to_add = read_unpacked_ids(values);
            ids.extend(to_add);
        } else if is_tombstone_key(&key) {
            todo!("tombstone key todo")
        } else {
            let to_add = unpack_128(&key, &values);
            ids.extend(to_add);
        }
    }

    Ok(ids)
}

/// The given key corresponds to the unpacked doc counter integers.
fn is_unpacked_key(key: &[u8]) -> bool {
    key[16..20] == [0, 0, 0, 0]
}

/// The given key corresponds to the tombstone doc counters.
fn is_tombstone_key(key: &[u8]) -> bool {
    key[16..20] == [255, 255, 255, 255]
}

fn is_key_for_packed(key: &[u8]) -> bool {
    !(is_unpacked_key(key) || is_tombstone_key(key))
}

fn read_unpacked_ids(encoded: sled::IVec) -> Vec<u32> {
    encoded
        .chunks_exact(4)
        .map(|bytes| {
            let mut id_bytes = [0u8; 4];
            id_bytes.copy_from_slice(bytes);
            u32::from_le_bytes(id_bytes)
        })
        .collect()
}

type NeedsUpdate = bool;
type Previous = Option<sled::IVec>;

/// Updates the unsorted, non bitpacked values
fn update_unsorted(
    tree: &sled::Tree,
    token: &[u8],
    doc: u32,
) -> sled::Result<(Previous, NeedsUpdate)> {
    let unsorted_key = unsorted_key(token);
    let mut resize_needed = false;

    let previous = tree.fetch_and_update(&unsorted_key, |existing| match existing {
        None => Some(sled::IVec::from_iter(doc.to_le_bytes())),
        Some(existing) => {
            if existing.len() == BitPacker4x::BLOCK_LEN * 4 {
                resize_needed = true;
                Some(sled::IVec::from_iter(doc.to_le_bytes()))
            } else {
                let mut existing = existing.to_vec();
                for x in &doc.to_le_bytes()[..] {
                    existing.push(*x);
                }

                let ivec = sled::IVec::from_iter(existing.into_iter());
                Some(ivec)
            }
        }
    })?;

    Ok((previous, resize_needed))
}

fn update_bitpacked(tree: &sled::Tree, token: &[u8], new_items: &[u8]) -> sled::Result<()> {
    let sorted_items = remove_bitpacked_and_merge(tree, token, new_items)?;
    assert_eq!(sorted_items.len() % BitPacker4x::BLOCK_LEN, 0);

    for block in sorted_items.chunks_exact(BitPacker4x::BLOCK_LEN) {
        let (key, value) = pack_128(token, block);
        let _ = tree.insert(key, value)?;
    }

    Ok(())
}

/// Get all the bitpacked items from the tree, removing them in the process,
/// and returning them, with the item in `to_merge` merged in, producing
/// a sorted vector.
fn remove_bitpacked_and_merge(
    tree: &sled::Tree,
    token: &[u8],
    to_merge: &[u8],
) -> sled::Result<Vec<u32>> {
    let mut to_merge: BinaryHeap<u32> = read_u32s_from_slice(to_merge).into_iter().collect();
    let sorted_iter = tree.scan_prefix(token);
    let mut items = Vec::with_capacity(sorted_iter.size_hint().0 * 256 + 256);

    // Performance optimization: don't update all in collection,
    // just i where min(new_items) < intial[i+1] and max(new_items) > initial[i]

    for collection in sorted_iter {
        let (key, _) = collection?;
        let values = tree.remove(&key)?.expect("key missing during re-encoding");

        if is_key_for_packed(&key) {
            let unpacked = unpack_128(&key, &values);

            for item in unpacked {
                if let Some(alternate) = to_merge.peek() {
                    if &item > alternate {
                        let next = to_merge.pop().unwrap();
                        items.push(next);
                        continue;
                    }
                }
                items.push(item);
            }
        }
    }

    Ok(items)
}

fn read_u32s_from_slice(slice: &[u8]) -> Vec<u32> {
    slice
        .chunks_exact(4)
        .map(|chunk| {
            let mut int = [0u8; 4];
            (&mut int).copy_from_slice(chunk);
            u32::from_le_bytes(int)
        })
        .collect()
}

/// Whether the sled tree contains the document-token pair
fn contains_doc_token_pair(tree: &sled::Tree, doc: u32, token: &[u8]) -> sled::Result<bool> {
    let doc_bytes = doc.to_le_bytes();
    if let Some(unsorted) = tree.get(unsorted_key(token))? {
        let f = |chunk: &[u8]| chunk[..] == doc_bytes[..];
        let in_unsorted = unsorted.chunks_exact(4).any(f);

        if in_unsorted {
            Ok(true)
        } else {
            packed_contains_doc_token_pair(tree, doc, token)
        }
    } else {
        Ok(false)
    }
}

/// Whether the sled tree contains the document-token pair in its packed values
fn packed_contains_doc_token_pair(tree: &sled::Tree, doc: u32, token: &[u8]) -> sled::Result<bool> {
    let partial_key = doc_token_partial_key(token, doc);

    let mut is_initial = tree.scan_prefix(&partial_key);
    if is_initial.next().is_some() {
        return Ok(true);
    }

    if let Some((key, values)) = tree.get_lt(&partial_key)? {
        if !is_unpacked_key(&key) && !is_tombstone_key(&key) && &key[0..16] == token {
            let unpacked = unpack_128(&key, &values);
            return Ok(unpacked.contains(&doc));
        }
    }

    Ok(false)
}

fn unsorted_key(token: &[u8]) -> Vec<u8> {
    let mut key = vec![0u8; 20];
    (&mut key[0..16]).copy_from_slice(token);
    key
}

/// Gets a token that partially matches the token and intial
/// document in a packed encoding.
///
/// Since packed encodings are sorted a less than or equal to
/// get from sled will return the 256 packed integers if they
/// exist or the previous integers.
fn doc_token_partial_key(token: &[u8], doc: u32) -> Vec<u8> {
    let mut key = vec![0u8; 20];
    (&mut key[0..16]).copy_from_slice(token);
    (&mut key[16..20]).copy_from_slice(&doc.to_le_bytes());
    key
}

fn initial_from_key(key: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    bytes[..].copy_from_slice(&key[16..20]);
    u32::from_le_bytes(bytes)
}

fn num_bits_from_key(key: &[u8]) -> u8 {
    key[20]
}

#[cfg(test)]
mod tests {
    use crate::token_encryption::demo_token;

    use super::*;

    #[test]
    fn test_packing() {
        // 128 randomly generated numbers from 0-10000.
        // Largest difference is 313.
        // 2^9 = 512, so 9 bits can represent all the differenced values.
        let test_numbers = [
            14, 37, 105, 220, 323, 367, 422, 522, 534, 622, 672, 695, 835, 947, 1039, 1256, 1295,
            1308, 1337, 1388, 1649, 1887, 1890, 1935, 1948, 2073, 2179, 2201, 2264, 2296, 2324,
            2416, 2435, 2515, 2617, 2670, 2982, 3140, 3216, 3253, 3378, 3396, 3411, 3443, 3687,
            3726, 3753, 3783, 3859, 3905, 3920, 3965, 3978, 4188, 4501, 4524, 4551, 4675, 4685,
            4738, 4775, 4829, 4846, 4947, 4988, 5009, 5111, 5213, 5261, 5399, 5400, 5443, 5477,
            5515, 5555, 5569, 5713, 5972, 6114, 6213, 6246, 6309, 6326, 6344, 6387, 6393, 6512,
            6580, 6582, 6608, 6704, 6810, 6872, 6897, 6979, 7018, 7046, 7070, 7175, 7222, 7385,
            7495, 7600, 7621, 7743, 7867, 8095, 8145, 8227, 8258, 8280, 8293, 8528, 8534, 8603,
            8661, 8790, 8880, 8911, 9050, 9217, 9251, 9314, 9408, 9447, 9472, 9534, 9784,
        ];

        let token = demo_token().into_vec();
        let (key, encoding) = pack_128(&token, &test_numbers);

        // 2048 bytes (UUID) -> 512 bytes (32 bit counter) -> 144 + 5 bytes (packed and diffed)!
        assert_eq!(144, encoding.len());
        assert_eq!(9, num_bits_from_key(&key));
        assert_eq!(test_numbers[0], initial_from_key(&key));

        let decoded = unpack_128(&key, &encoding);
        assert_eq!(&test_numbers[..], &decoded[..]);
    }
}
