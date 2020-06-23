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
        pub fn eei_set_storage_root(ptr: *const u8, len: usize);
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

    pub fn set_storage_root(buf: Vec<u8>) {
        unsafe {
            eei_set_storage_root(buf.as_ptr(), buf.len());
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

fn account_from_trie(key: NibbleKey, trie: &Node) -> Result<Account, &'static str> {
    if let Node::Leaf(_, ref acc_rlp) = trie[&key] {
        rlp::decode::<Account>(&acc_rlp).map_err(|_| "RLP error")
    } else {
        Err("account doesn't exist")
    }
}

fn execute_tx(
    from: &mut Account,
    to: &mut Account,
    trie: &Node,
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
                    let x: Vec<u8> = ByteKey::from(tx.from.clone()).into();
                    let mut keccak256 = Keccak256::new();
                    keccak256.input::<Vec<u8>>(x);
                    keccak256.input(&tx.data);
                    let thisaddr = keccak256.result()[..20].to_vec();
                    if NibbleKey::from(ByteKey::from(thisaddr)) != tx.to {
                        return Err("H(tx.from ++ tx.data) != tx.to");
                    }

                    // Fund the account
                    *tbalance = tx.value;
                    *fbalance -= tx.value;

                    // Initialize the state with the destination address,
                    // the origin address and the status byte.
                    *tstate = vec![0u8; 41];
                    (*tstate)[..20].copy_from_slice(&tx.data[..20]);
                    let f: Vec<u8> = ByteKey::from(tx.from.clone()).into();
                    (*tstate)[20..40].copy_from_slice(&f[..]);
                    // data[40] is therefore set to 0 == "transfer" mode
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

                    // Recover the senders' contract account so that
                    // its balance can be increased.
                    let mut keccak256 = Keccak256::new();
                    keccak256.input(&tstate[32..64]);
                    keccak256.input(&tstate[..32]);
                    let thisaddr = keccak256.result();
                    if let Account::Existing(_, _, ref mut cbalance, _, _) =
                        account_from_trie(NibbleKey::from(ByteKey::from(thisaddr.to_vec())), trie)?
                    {
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
                4 => {
                    // Check that the state's status byte is in "refund"
                    // mode.
                    if fstate[64] != 1 {
                        return Err("Contract isn't in refund mode");
                    }

                    // Check that the sender's address is the one that
                    // is stored in the state.
                    if NibbleKey::from(ByteKey::from(fstate[32..64].to_vec())) != tx.from {
                        return Err("Invalid tx recipient");
                    }

                    *fbalance += *tbalance;
                    *tbalance = 0;
                }
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

fn update(trie: &mut Node, from: &Account, to: &Account) {
    match (from, to) {
        (Account::Existing(fa, _, _, _, _), Account::Existing(ta, _, _, _, _)) => {
            trie.insert(fa, rlp::encode(from)).unwrap();
            trie.insert(ta, rlp::encode(to)).unwrap();

            eth::set_storage_root(trie.hash());
        }
        _ => panic!("Updated accounts can't be empty"),
    }
}

fn contract_main() -> Result<Vec<u8>, &'static str> {
    let mut payload = vec![0u8; eth::calldata_size()];
    eth::calldata(&mut payload, 0usize);
    let txdata: TxData = rlp::decode(&payload).unwrap();

    if let Ok(mut trie) = verify(&txdata) {
        for tx in txdata.txs {
            if let Node::Leaf(_, ref f) = trie[&tx.from] {
                let mut from = rlp::decode::<Account>(&f).unwrap();

                let mut to = if trie.has_key(&tx.to) {
                    if let Node::Leaf(_, ref t) = trie[&tx.to] {
                        rlp::decode::<Account>(&t).unwrap()
                    } else {
                        // Creation, value has to be checked.
                        Account::Existing(tx.to.clone(), 0, 0, vec![], vec![])
                    }
                } else {
                    Account::Existing(tx.to.clone(), 0, 0, vec![], vec![])
                };

                execute_tx(&mut from, &mut to, &trie, &tx)?;

                update(&mut trie, &from, &to);
            }
        }

        return Ok(trie.hash());
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
    use secp256k1::{
        recover as secp256k1_recover, sign as secp256k1_sign, verify as secp256k1_verify, Message,
        RecoveryId, SecretKey, Signature,
    };

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
    #[test]
    fn test_channel_creation() {
        let mut root = Node::default();

        // Create the first account
        let user1_skey = SecretKey::parse(&[1u8; 32]).unwrap();
        let msg = Message::parse_slice(&[0x55u8; 32]).unwrap();
        let (user1_sig, user1_recid) = secp256k1_sign(&msg, &user1_skey);
        let user1_pkey = secp256k1_recover(&msg, &user1_sig, &user1_recid).unwrap();
        let mut keccak256 = Keccak256::new();
        keccak256.input(&user1_pkey.serialize()[..]);
        let addr1 = keccak256.result_reset()[..20].to_vec();
        let user1_addr = NibbleKey::from(ByteKey::from(addr1.clone()));
        root.insert(
            &user1_addr,
            rlp::encode(&Account::Existing(
                user1_addr.clone(),
                1,
                1000,
                vec![],
                vec![],
            )),
        )
        .unwrap();

        // Create the second account
        let user2_skey = SecretKey::parse(&[2u8; 32]).unwrap();
        let (user2_sig, user2_recid) = secp256k1_sign(&msg, &user2_skey);
        let user2_pkey = secp256k1_recover(&msg, &user2_sig, &user2_recid).unwrap();
        keccak256.input(&user2_pkey.serialize()[..]);
        let addr2 = keccak256.result_reset()[..20].to_vec();
        let user2_addr = NibbleKey::from(ByteKey::from(addr2.clone()));
        root.insert(
            &user2_addr,
            rlp::encode(&Account::Existing(
                user2_addr.clone(),
                1,
                20,
                vec![],
                vec![],
            )),
        )
        .unwrap();

        // Intermediate contract address
        keccak256.input(&addr1);
        keccak256.input(&addr2);
        let contract_address =
            NibbleKey::from(ByteKey::from(keccak256.result_reset()[..20].to_vec()));
        // Channel-opening layer 2 transaction
        let mut open_tx = Tx {
            from: user1_addr.clone(),
            to: contract_address.clone(),
            data: addr2,
            nonce: 1,
            value: 100,
            signature: vec![0u8; 65],
            call: 1,
        };
        open_tx.sign(&user1_skey.serialize());

        // Create the proof containing the address of the channel creator,
        // as well as the addrss of the contract that will be created.
        let proof =
            make_multiproof(&root, vec![user1_addr.clone(), contract_address.clone()]).unwrap();

        // Layer 1 tx data
        let txdata = TxData {
            proof,
            txs: vec![open_tx],
        };

        eth::set_storage_root(root.hash());
        eth::set_calldata(rlp::encode(&txdata));

        contract_main().unwrap();

        // Check that the final root has been updated
        // to the proper value
        let mut newtrie = Node::default();
        newtrie
            .insert(
                &user1_addr,
                rlp::encode(&Account::Existing(
                    user1_addr.clone(),
                    2,
                    900,
                    vec![],
                    vec![],
                )),
            )
            .unwrap();
        newtrie
            .insert(
                &user2_addr,
                rlp::encode(&Account::Existing(
                    user2_addr.clone(),
                    1,
                    20,
                    vec![],
                    vec![],
                )),
            )
            .unwrap();
        newtrie
            .insert(
                &contract_address,
                rlp::encode(&Account::Existing(
                    contract_address.clone(),
                    0,
                    100,
                    vec![],
                    vec![
                        123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140, 63, 99, 27,
                        130, 242, 14, 181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205,
                        9, 152, 122, 184, 20, 30, 197, 0,
                    ],
                )),
            )
            .unwrap();
        let mut r = vec![0u8; 32];
        eth::get_storage_root(&mut r);
        assert_eq!(r, newtrie.hash());
    }
}
