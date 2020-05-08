extern crate jupiter_account;
extern crate multiproof_rs;
extern crate rlp;


use jupiter_account::{Account, Tx, TxData};

use multiproof_rs::{Multiproof, Node, ProofToTree, Tree};

fn verify(txdata: &[u8]) -> Result<bool, &str> {
    return Err("not implemented");
}

fn update<K>(trie: &dyn Tree<K>, from: &Account, to: &Account) -> Vec<u8> {
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main() {
}

#[cfg(test)]
mod tests {
}
