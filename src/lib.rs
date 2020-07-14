extern crate jupiter_account;
extern crate multiproof_rs;
extern crate rlp;
extern crate secp256k1;
extern crate sha3;

#[cfg_attr(not(target_arch = "wasm32"), path = "eth_test.rs")]
#[cfg_attr(target_arch = "wasm32", path = "eth_wasm.rs")]
pub mod eth;

use jupiter_account::{Account, Tx, TxData};
use multiproof_rs::{ByteKey, NibbleKey, Node, ProofToTree, Tree};
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
    trie: &mut Node,
    tx: &Tx,
) -> Result<(), &'static str> {
    let mut updated_accounts = Vec::<&Account>::new();
    if let Account::Existing(_, ref mut fnonce, ref mut fbalance, _, _) = from {
        if let Account::Existing(_, tnonce, ref mut tbalance, _, ref mut tstate) = to {
            if *fnonce != tx.nonce {
                return Err("invalid nonce");
            }
            *fnonce += 1;

            if *fbalance < tx.value {
                return Err("insufficent balance");
            }

            let (valid, txsigner_addr) = tx.sig_check();
            if !valid {
                return Err("invalid tx signature");
            }

            match tx.call {
                // This is a simple value transfer tx
                0 => {
                    if txsigner_addr != tx.from {
                        return Err("tx signer != tx.from");
                    }

                    *fbalance -= tx.value;
                    *tbalance += tx.value;

                    updated_accounts.push(from);
                    updated_accounts.push(to);
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

                    updated_accounts.push(from);
                    updated_accounts.push(to);
                }
                // Pay the other contract. The "from" address is the one
                // of the sender's contract and the "to" address is that
                // of the recipient (NOT the recipient's contract).
                2 => {
                    // Check that the state's status byte is in "transfer"
                    // mode.
                    if tstate[40] != 0 {
                        return Err("Contract isn't in transfer mode");
                    }

                    // Check that the transaction is signed by the account
                    // controlling this contract, i.e. the value stored at
                    // state[20..40].
                    if txsigner_addr != NibbleKey::from(ByteKey::from(tstate[20..40].to_vec())) {
                        return Err("Tx isn't signed by the proper address");
                    }

                    // The recipient is the contract holding the funds,
                    // decrease its balance.
                    *tbalance -= tx.value;
                    *tnonce += 1;

                    // Recover the other party's contract account so that
                    // its balance can be increased.
                    let mut keccak256 = Keccak256::new();
                    keccak256.input(&tstate[..40]);
                    let otheraddr = keccak256.result();
                    let mut other_account = account_from_trie(
                        NibbleKey::from(ByteKey::from(otheraddr.to_vec())),
                        trie,
                    )?;
                    if let Account::Existing(_, _, ref mut cbalance, _, _) = other_account {
                        // Increase the senders' contract balance.
                        *cbalance += tx.value;

                        update(trie, vec![to, &other_account, from]);
                    } else {
                        return Err("Contract isn't available");
                    }
                }
                // Close channel. This will simply change the status
                // byte to mark that the contract is no longer in the
                // 'transfer' mode and instead in the 'refund' mode.
                3 => {
                    // NOTE the sender can pass some value here, it
                    // won't be transferred.

                    // Check that the state's status byte is in "transfer"
                    // mode.
                    if tstate[40] != 0 {
                        return Err("Contract isn't in transfer mode");
                    }

                    // Check that the sender's address is the one that
                    // is stored in the state.
                    if NibbleKey::from(ByteKey::from(tstate[20..40].to_vec())) != txsigner_addr {
                        return Err("Invalid tx recipient");
                    }

                    tstate[40] = 1;

                    *tnonce += 1;
                    updated_accounts.push(from);
                    updated_accounts.push(to);
                }
                // Refund
                4 => {
                    // Check that the state's status byte is in "refund"
                    // mode.
                    if tstate[40] != 1 {
                        return Err("Contract isn't in refund mode");
                    }

                    // Check that the sender's address is the one that
                    // is stored in the state.
                    if NibbleKey::from(ByteKey::from(tstate[20..40].to_vec())) != txsigner_addr {
                        return Err("Invalid tx recipient");
                    }

                    *fbalance += *tbalance;
                    *tbalance = 0;

                    updated_accounts.push(from);
                    updated_accounts.push(to);
                }
                _ => return Err("unknown tx.call"),
            }

            update(trie, updated_accounts);
            Ok(())
        } else {
            Err("Recipient account shouldn't be empty at this point")
        }
    } else {
        Err("Tried to send from an empty account")
    }
}

fn update(trie: &mut Node, accounts: Vec<&Account>) {
    for account in accounts.iter() {
        match account {
            Account::Existing(a, _, _, _, _) => {
                trie.insert(a, rlp::encode(*account)).unwrap();
            }

            _ => panic!("Updated accounts can't be empty"),
        }
    }
    eth::set_storage_root(trie.hash());
}

pub fn control_contract(addr1: &NibbleKey, addr2: &NibbleKey) -> NibbleKey {
    let addr1_bytes: Vec<u8> = ByteKey::from(addr1.clone()).into();
    let addr2_bytes: Vec<u8> = ByteKey::from(addr2.clone()).into();

    let mut keccak256 = Keccak256::new();
    keccak256.input(&addr1_bytes);
    keccak256.input(&addr2_bytes);
    NibbleKey::from(ByteKey::from(keccak256.result_reset()[..20].to_vec()))
}

pub fn contract_main() -> Result<Vec<u8>, &'static str> {
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

                execute_tx(&mut from, &mut to, &mut trie, &tx)?;
            }
        }

        return Ok(trie.hash());
    }
    Err("could not verify proof")
}

#[cfg(target_arch = "wasm32")]
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
    use secp256k1::SecretKey;

    #[test]
    fn test_recover_account_no_keys() {
        eth::reset();

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
        eth::reset();

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
    fn test_channel_creation() {
        eth::reset();

        let mut root = Node::default();

        // Create the first account
        let user1_skey = SecretKey::parse(&[1u8; 32]).unwrap();
        let mut account1 = Account::from(&user1_skey);
        let addr1 = match account1 {
            Account::Existing(ref a, ref mut n, ref mut b, _, _) => {
                *n = 1;
                *b = 1000;
                a
            }
            _ => panic!("expected existing account"),
        };
        root.insert(&addr1, rlp::encode(&account1)).unwrap();

        // Create the second account
        let user2_skey = SecretKey::parse(&[2u8; 32]).unwrap();
        let mut account2 = Account::from(&user2_skey);
        let addr2 = match account2 {
            Account::Existing(ref a, ref mut n, ref mut b, _, _) => {
                *n = 1;
                *b = 20;
                a
            }
            _ => panic!("expected existing account"),
        };
        root.insert(&addr2, rlp::encode(&account2)).unwrap();

        // Intermediate contract address
        let contract_address = control_contract(addr1, addr2);

        // Channel-opening layer 2 transaction
        let mut open_tx = Tx {
            from: addr1.clone(),
            to: contract_address.clone(),
            data: ByteKey::from(addr2.clone()).into(),
            nonce: 1,
            value: 100,
            signature: vec![0u8; 65],
            call: 1,
        };
        open_tx.sign(&user1_skey.serialize());

        // Create the proof containing the address of the channel creator,
        // as well as the addrss of the contract that will be created.
        let proof = make_multiproof(&root, vec![addr1.clone(), contract_address.clone()]).unwrap();

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
        let endstate = vec![
            (addr1, 2, 900, vec![]),
            (addr2, 1, 20, vec![]),
            (
                &contract_address,
                0,
                100,
                vec![
                    123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140, 63, 99, 27,
                    130, 242, 14, 181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9,
                    152, 122, 184, 20, 30, 197, 0,
                ],
            ),
        ];
        let mut newtrie = Node::default();
        for (addr, nonce, balance, data) in endstate.iter() {
            newtrie
                .insert(
                    &addr,
                    rlp::encode(&Account::Existing(
                        (*addr).clone(),
                        *nonce,
                        *balance,
                        vec![],
                        data.to_vec(),
                    )),
                )
                .unwrap();
        }

        let mut r = vec![0u8; 32];
        eth::get_storage_root(&mut r);
        assert_eq!(r, newtrie.hash());
    }

    #[test]
    fn test_channel_send() {
        eth::reset();

        let mut root = Node::default();

        // Create the first account
        let user1_skey = SecretKey::parse(&[1u8; 32]).unwrap();
        let mut account1 = Account::from(&user1_skey);
        let addr1 = match account1 {
            Account::Existing(ref a, ref mut n, ref mut b, _, _) => {
                *n = 1;
                *b = 900;
                a
            }
            _ => panic!("expected existing account"),
        };
        root.insert(&addr1, rlp::encode(&account1)).unwrap();

        // Create the second account
        let user2_skey = SecretKey::parse(&[2u8; 32]).unwrap();
        let mut account2 = Account::from(&user2_skey);
        let addr2 = match account2 {
            Account::Existing(ref a, ref mut n, ref mut b, _, _) => {
                *n = 1;
                *b = 20;
                a
            }
            _ => panic!("expected existing account"),
        };
        root.insert(&addr2, rlp::encode(&account2)).unwrap();

        // Intermediate contract address for user1
        let contract_address1 = control_contract(&addr1, &addr2);
        root.insert(
            &contract_address1,
            rlp::encode(&Account::Existing(
                contract_address1.clone(),
                0,
                100,
                vec![],
                vec![
                    123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140, 63, 99, 27,
                    130, 242, 14, 181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9,
                    152, 122, 184, 20, 30, 197, 0,
                ],
            )),
        )
        .unwrap();

        // Intermediate contract address for user2
        let contract_address2 = control_contract(&addr2, &addr1);
        root.insert(
            &contract_address2,
            rlp::encode(&Account::Existing(
                contract_address2.clone(),
                0,
                100,
                vec![],
                vec![
                    181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9, 152, 122, 184,
                    20, 30, 197, 123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140,
                    63, 99, 27, 130, 242, 14, 0,
                ],
            )),
        )
        .unwrap();

        // Channel-opening layer 2 transaction
        let mut open_tx = Tx {
            from: addr1.clone(),
            to: contract_address1.clone(),
            data: ByteKey::from(addr2.clone()).into(),
            nonce: 1,
            value: 10,
            signature: vec![0u8; 65],
            call: 2,
        };
        open_tx.sign(&user1_skey.serialize());

        // Create the proof containing the address of the channel creator,
        // as well as the addrss of the contract that will be created.
        let proof = make_multiproof(
            &root,
            vec![
                addr1.clone(),
                contract_address1.clone(),
                contract_address2.clone(),
                addr2.clone(),
            ],
        )
        .unwrap();

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
        let endstate = vec![
            (addr1, 2, 900, vec![]),
            (addr2, 1, 20, vec![]),
            (
                &contract_address1,
                1,
                90,
                vec![
                    123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140, 63, 99, 27,
                    130, 242, 14, 181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9,
                    152, 122, 184, 20, 30, 197, 0,
                ],
            ),
            (
                &contract_address2,
                0,
                110,
                vec![
                    181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9, 152, 122, 184,
                    20, 30, 197, 123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140,
                    63, 99, 27, 130, 242, 14, 0,
                ],
            ),
        ];
        let mut newtrie = Node::default();
        for (addr, nonce, balance, data) in endstate.iter() {
            newtrie
                .insert(
                    &addr,
                    rlp::encode(&Account::Existing(
                        (*addr).clone(),
                        *nonce,
                        *balance,
                        vec![],
                        data.to_vec(),
                    )),
                )
                .unwrap();
        }

        let mut r = vec![0u8; 32];
        eth::get_storage_root(&mut r);
        assert_eq!(r, newtrie.hash());
    }

    #[test]
    fn test_channel_close() {
        eth::reset();

        let mut root = Node::default();

        // Create the first account
        let user1_skey = SecretKey::parse(&[1u8; 32]).unwrap();
        let mut account1 = Account::from(&user1_skey);
        let addr1 = match account1 {
            Account::Existing(ref a, ref mut n, ref mut b, _, _) => {
                *n = 1;
                *b = 900;
                a
            }
            _ => panic!("expected existing account"),
        };
        root.insert(&addr1, rlp::encode(&account1)).unwrap();

        // Create the second account
        let user2_skey = SecretKey::parse(&[2u8; 32]).unwrap();
        let mut account2 = Account::from(&user2_skey);
        let addr2 = match account2 {
            Account::Existing(ref a, ref mut n, ref mut b, _, _) => {
                *n = 1;
                *b = 20;
                a
            }
            _ => panic!("expected existing account"),
        };
        root.insert(&addr2, rlp::encode(&account2)).unwrap();

        // Intermediate contract address for user1
        let contract_address1 = control_contract(&addr1, &addr2);
        root.insert(
            &contract_address1,
            rlp::encode(&Account::Existing(
                contract_address1.clone(),
                1,
                90,
                vec![],
                vec![
                    123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140, 63, 99, 27,
                    130, 242, 14, 181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9,
                    152, 122, 184, 20, 30, 197, 0,
                ],
            )),
        )
        .unwrap();

        // Intermediate contract address for user2
        let contract_address2 = control_contract(&addr2, &addr1);
        root.insert(
            &contract_address2,
            rlp::encode(&Account::Existing(
                contract_address2.clone(),
                0,
                110,
                vec![],
                vec![
                    181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9, 152, 122, 184,
                    20, 30, 197, 123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140,
                    63, 99, 27, 130, 242, 14, 0,
                ],
            )),
        )
        .unwrap();

        // Channel-opening layer 2 transaction
        let mut open_tx = Tx {
            from: addr1.clone(),
            to: contract_address1.clone(),
            data: ByteKey::from(addr2.clone()).into(),
            nonce: 1,
            value: 0,
            signature: vec![0u8; 65],
            call: 3,
        };
        open_tx.sign(&user1_skey.serialize());

        // Create the proof containing the address of the channel creator,
        // as well as the addrss of the contract that will be created.
        let proof = make_multiproof(
            &root,
            vec![
                addr1.clone(),
                contract_address1.clone(),
                contract_address2.clone(),
                addr2.clone(),
            ],
        )
        .unwrap();

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
        let endstate = vec![
            (addr1, 2, 900, vec![]),
            (addr2, 1, 20, vec![]),
            (
                &contract_address1,
                2,
                90,
                vec![
                    123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140, 63, 99, 27,
                    130, 242, 14, 181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9,
                    152, 122, 184, 20, 30, 197, 1,
                ],
            ),
            (
                &contract_address2,
                0,
                110,
                vec![
                    181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9, 152, 122, 184,
                    20, 30, 197, 123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140,
                    63, 99, 27, 130, 242, 14, 0,
                ],
            ),
        ];
        let mut newtrie = Node::default();
        for (addr, nonce, balance, data) in endstate.iter() {
            newtrie
                .insert(
                    &addr,
                    rlp::encode(&Account::Existing(
                        (*addr).clone(),
                        *nonce,
                        *balance,
                        vec![],
                        data.to_vec(),
                    )),
                )
                .unwrap();
        }

        let mut r = vec![0u8; 32];
        eth::get_storage_root(&mut r);
        assert_eq!(r, newtrie.hash());
    }

    #[test]
    fn test_channel_refund() {
        eth::reset();

        let mut root = Node::default();

        // Create the first account
        let user1_skey = SecretKey::parse(&[1u8; 32]).unwrap();
        let mut account1 = Account::from(&user1_skey);
        let addr1 = match account1 {
            Account::Existing(ref a, ref mut n, ref mut b, _, _) => {
                *n = 1;
                *b = 900;
                a
            }
            _ => panic!("expected existing account"),
        };
        root.insert(&addr1, rlp::encode(&account1)).unwrap();

        // Create the second account
        let user2_skey = SecretKey::parse(&[2u8; 32]).unwrap();
        let mut account2 = Account::from(&user2_skey);
        let addr2 = match account2 {
            Account::Existing(ref a, ref mut n, ref mut b, _, _) => {
                *n = 1;
                *b = 20;
                a
            }
            _ => panic!("expected existing account"),
        };
        root.insert(&addr2, rlp::encode(&account2)).unwrap();

        // Intermediate contract address for user1
        let contract_address1 = control_contract(&addr1, &addr2);
        root.insert(
            &contract_address1,
            rlp::encode(&Account::Existing(
                contract_address1.clone(),
                2,
                90,
                vec![],
                vec![
                    123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140, 63, 99, 27,
                    130, 242, 14, 181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9,
                    152, 122, 184, 20, 30, 197, 1,
                ],
            )),
        )
        .unwrap();

        // Channel-opening layer 2 transaction
        let mut open_tx = Tx {
            from: addr1.clone(),
            to: contract_address1.clone(),
            data: ByteKey::from(addr2.clone()).into(),
            nonce: 1,
            value: 0,
            signature: vec![0u8; 65],
            call: 4,
        };
        open_tx.sign(&user1_skey.serialize());

        // Create the proof containing the address of the channel creator,
        // as well as the addrss of the contract that will be created.
        let proof = make_multiproof(
            &root,
            vec![addr1.clone(), contract_address1.clone(), addr2.clone()],
        )
        .unwrap();

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
        let endstate = vec![
            (addr1, 2, 990, vec![]),
            (addr2, 1, 20, vec![]),
            (
                &contract_address1,
                2,
                0,
                vec![
                    123, 76, 14, 99, 195, 95, 145, 247, 99, 59, 196, 219, 252, 140, 63, 99, 27,
                    130, 242, 14, 181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9,
                    152, 122, 184, 20, 30, 197, 1,
                ],
            ),
        ];
        let mut newtrie = Node::default();
        for (addr, nonce, balance, data) in endstate.iter() {
            newtrie
                .insert(
                    &addr,
                    rlp::encode(&Account::Existing(
                        (*addr).clone(),
                        *nonce,
                        *balance,
                        vec![],
                        data.to_vec(),
                    )),
                )
                .unwrap();
        }

        let mut r = vec![0u8; 32];
        eth::get_storage_root(&mut r);
        assert_eq!(r, newtrie.hash());
    }
}
