extern crate jupiter_account;
extern crate multiproof_rs;
extern crate rlp;

extern "C" {
    pub fn revert();
    pub fn finish(data: *const u8, len: usize);
    pub fn calldata(buf: *const u8, offset: u64, len: usize);
    pub fn calldata_size() -> usize;

    pub fn get_storage_root() -> Vec<u8>;
}

use jupiter_account::{Account, TxData};

use multiproof_rs::{Node, ProofToTree, Tree};

fn verify(txdata: &TxData) -> Result<Node, String> {
    let trie: Node = txdata.proof.rebuild()?;

    // Check that the hash is the same as the root's
    // storage
    if trie.hash() != unsafe { get_storage_root() } {
        return Err(format!(
            "Storage and proof root hashes differ: {:?} != {:?}",
            unsafe { get_storage_root() },
            trie.hash()
        ));
    }

    // Check that all txs' from addresses are in the trie
    for tx in txdata.txs.iter() {
        if !trie.has_key(&tx.from) {
            return Err(format!("key {:?} isn't in trie", tx.from));
        }
    }

    Ok(trie)
}

fn update(trie: &mut Node, from: &Account, to: &Account) -> Vec<u8> {
    match (from, to) {
        (Account::Existing(fa, _, _, _, _), Account::Existing(ta, _, _, _, _)) => {
            trie.insert(fa, rlp::encode(from)).unwrap();
            trie.insert(ta, rlp::encode(to)).unwrap();

            return trie.hash();
        }
        _ => panic!("Updated accounts can't be empty"),
    }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main() {
    let mut payload = vec![0u8; unsafe { calldata_size() }];
    unsafe {
        calldata(payload.as_mut_ptr(), 0, calldata_size());
    }
    let txdata: TxData = rlp::decode(&payload).unwrap();
    let res = Vec::new();

    if let Ok(mut trie) = verify(&txdata) {
        for tx in txdata.txs {
            if let Node::Leaf(_, ref f) = trie[&tx.from] {
                let mut from = rlp::decode::<Account>(&f).unwrap();

                if from.balance() < tx.value {
                    unsafe {
                        revert();
                    }
                }
                let from_balance = from.balance_mut().unwrap();
                *from_balance -= tx.value;

                if from.nonce() != tx.nonce {
                    unsafe {
                        revert();
                    }
                }
                let from_nonce = from.nonce_mut().unwrap();
                *from_nonce += 1;

                let to = if let Node::Leaf(_, ref t) = trie[&tx.to] {
                    let mut to = rlp::decode::<Account>(&t).unwrap();

                    let to_balance = to.balance_mut().unwrap();
                    *to_balance += tx.value;
                    to
                } else {
                    // Creation, value has to be checked,
                    // which means that I have to make sure
                    // that precompiles have access to value
                    Account::Existing(tx.to, 0, tx.value, vec![], false)
                };
                update(&mut trie, &from, &to);
            }
        }

        unsafe {
            finish(res.as_ptr(), res.len());
        }
    }
    unsafe {
        revert();
    }
}

#[cfg(test)]
mod tests {
}
