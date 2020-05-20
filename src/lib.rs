extern crate jupiter_account;
extern crate multiproof_rs;
extern crate rlp;
extern crate secp256k1;
extern crate sha3;

#[cfg(not(test))]
mod eth {
    extern "C" {
        pub fn eei_revert();
        pub fn eei_finish(data: *const u8, len: usize);
        pub fn eei_calldata(buf: *const u8, offset: usize, len: usize);
        pub fn eei_calldata_size() -> usize;

        pub fn eei_get_storage_root(ptr: *mut u8, len: usize);
    }

    pub fn revert() {
        unsafe {
            eei_revert();
        }
    }

    pub fn finish(res: Vec<u8>) {
        unsafe {
            eei_finish(res.as_ptr(), res.len());
        }
    }

    pub fn calldata(buf: &mut Vec<u8>, offset: usize) {
        unsafe {
            eei_calldata(buf.as_mut_ptr(), offset, buf.len());
        }
    }

    pub fn calldata_size() -> usize {
        unsafe { eei_calldata_size() }
    }

    pub fn get_storage_root(buf: &mut Vec<u8>) {
        unsafe {
            eei_get_storage_root(buf.as_mut_ptr(), buf.len());
        }
    }
}

#[cfg(test)]
mod eth {
    static mut CD: Vec<u8> = Vec::new();
    static mut ROOT: Vec<u8> = Vec::new();
    static mut RESDATA: Vec<u8> = Vec::new();

    pub fn revert() {}

    pub fn finish(res: Vec<u8>) {
        unsafe {
            RESDATA.copy_from_slice(&res[..]);
        }
    }

    pub fn calldata(buf: &mut Vec<u8>, offset: usize) {
        let end = offset + buf.len();
        println!("{} {} {}", offset, end, unsafe { CD.len() });
        unsafe {
            buf.copy_from_slice(&CD[offset..end]);
        }
    }

    pub fn calldata_size() -> usize {
        return unsafe { CD.len() };
    }

    pub fn get_storage_root(buf: &mut Vec<u8>) {
        unsafe {
            buf.copy_from_slice(&ROOT[..]);
        }
    }

    pub fn set_storage_root(buf: Vec<u8>) {
        if buf.len() != 32 {
            panic!("Invalid root length");
        }
        unsafe {
            ROOT.resize(32, 0u8);
            for (i, b) in buf.iter().enumerate() {
                ROOT[i] = *b;
            }
        }
    }
    pub fn set_calldata(buf: Vec<u8>) {
        for b in buf.iter() {
            unsafe {
                CD.push(*b);
            }
        }
    }
}

use jupiter_account::{Account, TxData};
use multiproof_rs::{ByteKey, NibbleKey, Node, ProofToTree, Tree};
use secp256k1::{
    recover as secp256k1_recover, verify as secp256k1_verify, Message, RecoveryId, Signature,
};
use sha3::{Digest, Keccak256};

fn verify(txdata: &TxData) -> Result<Node, String> {
    let trie: Node = txdata.proof.rebuild()?;
    let mut storage_root = vec![0u8; 32];
    eth::get_storage_root(&mut storage_root);

    // Check that the hash is the same as the root's
    // storage
    if trie.hash() != storage_root {
        return Err(format!(
            "Storage and proof root hashes differ: {:?} != {:?}",
            storage_root,
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

            trie.hash()
        }
        _ => panic!("Updated accounts can't be empty"),
    }
}

fn sig_check(txdata: &TxData) -> (bool, Vec<u8>) {
    // Recover the signature from the tx data.
    // All transactions have to come from the
    // same sender to be accepted.
    let mut keccak256 = Keccak256::new();
    for tx in txdata.txs.iter() {
        keccak256.input(rlp::encode(tx));
    }
    let message_data = keccak256.result_reset();
    let message = Message::parse_slice(&message_data).unwrap();
    let signature = Signature::parse_slice(&txdata.signature[..64]).unwrap();
    let recover = RecoveryId::parse(txdata.signature[64]).unwrap();
    let pkey = secp256k1_recover(&message, &signature, &recover).unwrap();

    // Verify the signature
    if !secp256k1_verify(&message, &signature, &pkey) {
        return (false, Vec::new());
    }

    // Get the address
    keccak256.input(&pkey.serialize()[..]);
    (true, keccak256.result()[..20].to_vec())
}

fn contract_main() -> Result<Vec<u8>, &'static str> {
    let mut payload = vec![0u8; eth::calldata_size()];
    eth::calldata(&mut payload, 0usize);
    let txdata: TxData = rlp::decode(&payload).unwrap();
    let res = Vec::new();

    let (sigok, sig_addr) = sig_check(&txdata);
    if !sigok {
        return Err("invalid signature");
    }

    if let Ok(mut trie) = verify(&txdata) {
        for tx in txdata.txs {
            if let Node::Leaf(_, ref f) = trie[&tx.from] {
                let mut from = rlp::decode::<Account>(&f).unwrap();

                // Check that the sender of the l2 tx is also the
                // one that signed the txdata.
                if NibbleKey::from(ByteKey::from(sig_addr.to_vec())) != tx.from {
                    return Err("l2 tx sender != l1 tx sender");
                }

                if from.balance() < tx.value {
                    return Err("insufficent balance");
                }
                let from_balance = from.balance_mut().unwrap();
                *from_balance -= tx.value;

                if from.nonce() != tx.nonce {
                    return Err("invalid nonce");
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

        return Ok(res);
    }
    Err("could not verify proof")
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main() {
    match contract_main() {
        Ok(res) => eth::finish(res),
        Err(_) => eth::revert(),
    }
}

#[cfg(test)]
mod tests {
    use super::multiproof_rs::{make_multiproof, NibbleKey, Node};
    use super::*;

    #[test]
    fn test_recover_account_no_keys() {
        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![0u8; 32]), vec![0u8; 32])
            .unwrap();
        root.insert(&NibbleKey::from(vec![1u8; 32]), vec![1u8; 32])
            .unwrap();
        let proof = make_multiproof(&root, vec![NibbleKey::from(vec![1u8; 32])]).unwrap();
        let mut txdata = TxData {
            proof,
            txs: vec![],
            signature: vec![0u8; 65],
        };

        txdata.sign(&[1; 32]);

        eth::set_storage_root(root.hash());
        eth::set_calldata(rlp::encode(&txdata));

        contract_main().unwrap();

        // Check that the root wasn't updated
        let mut r = vec![0u8; 32];
        eth::get_storage_root(&mut r);
        assert_eq!(r, root.hash());
    }

    #[test]
    fn test_validate_keys() {
        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![0u8; 32]), vec![0u8; 32])
            .unwrap();
        root.insert(&NibbleKey::from(vec![1u8; 32]), vec![1u8; 32])
            .unwrap();
        let proof = make_multiproof(&root, vec![NibbleKey::from(vec![1u8; 32])]).unwrap();
        let mut txdata = TxData {
            proof,
            txs: vec![],
            signature: vec![0u8; 65],
        };

        txdata.sign(&[1; 32]);

        println!("root hash={:?}", root.hash());
        eth::set_storage_root(root.hash());
        eth::set_calldata(rlp::encode(&txdata));

        contract_main().unwrap();

        // Check that the root wasn't updated
        let mut r = vec![0u8; 32];
        eth::get_storage_root(&mut r);
        assert_eq!(r, root.hash());
    }
}
