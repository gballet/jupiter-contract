extern crate jupiter_account;
extern crate multiproof_rs;
extern crate rlp;
extern crate secp256k1;
extern crate sha3;

use sha3::{Digest, Keccak256};

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

use jupiter_account::{Account, Tx, TxData};
use multiproof_rs::{ByteKey, NibbleKey, Node, ProofToTree, Tree};

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

fn execute_tx(
    from: &mut Account,
    to: &mut Account,
    contract: &mut Account,
    tx: &Tx,
) -> Result<(), &'static str> {
    if let Account::Existing(_, ref mut fnonce, ref mut fbalance, _, ref mut fstate) = from {
        if let Account::Existing(_, tnonce, ref mut tbalance, _, ref mut tstate) = to {
            if *fnonce != tx.nonce {
                return Err("invalid nonce");
            }
            *fnonce += 1;

            if *fbalance < tx.value {
                return Err("insufficent balance");
            }

            let (valid, txsender_addr) = tx.sig_check();
            if !valid {
                return Err("invalid tx signature");
            }

            match tx.call {
                // This is a simple value transfer tx
                0 => {
                    if txsender_addr != tx.from {
                        return Err("tx signer != tx.from");
                    }

                    *fbalance -= tx.value;
                    *tbalance += tx.value;
                }
                // Create channel. This is mostly like a simple value
                // transfer, however the account has to not already
                // exist and it will be endowed with a data segment
                // containing the address of the other party, as well
                // as a status byte saying it's in 'transfer' mode.
                1 => {
                    // Check that the account doesn't already exist
                    if *tnonce != 0 {
                        return Err("Trying to overwrite an existing account");
                    }

                    // Update balance to fund the account
                    if *tbalance > 0 {
                        return Err("Trying to overwrite a funded account");
                    }

                    // Check that the data field corresponds to the sender
                    // address that this contract is meant to interface with
                    let mut keccak256 = Keccak256::new();
                    keccak256.input::<Vec<u8>>(ByteKey::from(tx.from.clone()).into());
                    keccak256.input(&tx.data);
                    let thisaddr = keccak256.result();
                    if NibbleKey::from(ByteKey::from(thisaddr.to_vec())) != tx.to {
                        return Err("H(from, data) != tx.to");
                    }

                    // Fund the account
                    *tbalance = tx.value;
                    *fbalance -= tx.value;

                    // Initialize the state with the destination address,
                    // the origin address and the status byte.
                    *tstate = vec![0u8; 65];
                    (*tstate)[..32].copy_from_slice(&tx.data[..32]);
                    let f: Vec<u8> = ByteKey::from(tx.from.clone()).into();
                    (*tstate)[32..64].copy_from_slice(&f[..]);
                    // data[64] is therefore set to 0 == "transfer" mode
                }
                // Pay the other contract. The "from" address is the one
                // of the sender's contract and the "to" address is that
                // of the recipient (NOT the recipient's contract).
                2 => {
                    // Check that the state's status byte is in "transfer"
                    // mode.
                    if fstate[64] != 0 {
                        return Err("Contract isn't in transfer mode");
                    }

                    // Check that the sender's address is the one stored
                    // in the state.
                    if NibbleKey::from(ByteKey::from(fstate[..32].to_vec())) != tx.from {
                        return Err("Invalid tx sender");
                    }

                    // The recipient is the contract holding the funds,
                    // decrease its balance.
                    *tbalance -= tx.value;

                    // Calculate the senders' contract account so that
                    // it can be recovered and its balance increased.
                    if let Account::Existing(ref addr, _, ref mut cbalance, _, _) = contract {
                        // Check that the address is the right one
                        let mut keccak256 = Keccak256::new();
                        keccak256.input(&tstate[32..64]);
                        keccak256.input(&tstate[..32]);
                        let thisaddr = keccak256.result();
                        if &NibbleKey::from(ByteKey::from(thisaddr.to_vec())) != addr {
                            return Err("receiver address is not authorized by contract");
                        }

                        // Increase the senders' contract balance.
                        *cbalance += tx.value;
                    } else {
                        return Err("Contract isn't available");
                    }
                }
                // Close channel. This will simply change the status
                // byte to mark that the contract is no longer in the
                // 'transfer' mode and instead in the 'refund' mode.
                3 => {
                    // NOTE the sender can set some value here, it
                    // won't be transferred.

                    // Check that the state's status byte is in "transfer"
                    // mode.
                    if fstate[64] != 0 {
                        return Err("Contract isn't in transfer mode");
                    }

                    // Check that the sender's address is the one that
                    // is stored in the state.
                    if NibbleKey::from(ByteKey::from(fstate[..32].to_vec())) != tx.from {
                        return Err("Invalid tx recipient");
                    }

                    fstate[64] = 1;
                }
                // Refund
                4 => {}
                _ => return Err("unknown tx.call"),
            }

            Ok(())
        } else {
            Err("Recipient account shouldn't be empty at this point")
        }
    } else {
        Err("Tried to send from an empty account")
    }
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

fn contract_main() -> Result<Vec<u8>, &'static str> {
    let mut payload = vec![0u8; eth::calldata_size()];
    eth::calldata(&mut payload, 0usize);
    let txdata: TxData = rlp::decode(&payload).unwrap();
    let res = Vec::new();

    if let Ok(mut trie) = verify(&txdata) {
        for tx in txdata.txs {
            if let Node::Leaf(_, ref f) = trie[&tx.from] {
                let mut from = rlp::decode::<Account>(&f).unwrap();

                let mut to = if let Node::Leaf(_, ref t) = trie[&tx.to] {
                    rlp::decode::<Account>(&t).unwrap()
                } else {
                    // Creation, value has to be checked.
                    Account::Existing(tx.to.clone(), 0, tx.value, vec![], vec![])
                };

                execute_tx(&mut from, &mut to, &mut Account::Empty, &tx)?;

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
        let txdata = TxData { proof, txs: vec![] };

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
        let txdata = TxData { proof, txs: vec![] };

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
