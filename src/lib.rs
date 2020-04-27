extern crate jupiter_account;
extern crate multiproof_rs;
extern crate rlp;

use jupiter_account;
use jupiter_account::Account;


#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main() {
}

#[cfg(test)]
mod tests {
}
