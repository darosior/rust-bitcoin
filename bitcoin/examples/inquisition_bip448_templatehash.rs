// SPDX-License-Identifier: CC0-1.0

//! Sign a BIP446 `TemplateHash` for a Bitcoin Inquisition/BIP448 tapscript spend.
//!
//! The common script pattern is `OP_TEMPLATEHASH OP_INTERNALKEY OP_CHECKSIGFROMSTACK`. The signature
//! is a raw 64-byte BIP340 Schnorr signature over the 32-byte template hash, with no Taproot sighash
//! byte appended.

use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute;
use bitcoin::opcodes::all::{OP_CHECKSIGFROMSTACK, OP_INTERNALKEY, OP_TEMPLATEHASH};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

fn main() {
    let secp = Secp256k1::new();
    let keypair = example_keypair();
    let internal_key = keypair.x_only_public_key().0;
    let script = bip448_rebindable_script();

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("valid taproot tree")
        .finalize(&secp, internal_key)
        .expect("finalizable taproot tree");
    let control_block = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("script is in tree");

    let input = TxIn {
        previous_output: OutPoint { txid: Txid::from_byte_array([0x11; 32]), vout: 0 },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let destination = ScriptBuf::new_p2tr(&secp, internal_key, None);
    let output = TxOut { value: Amount::from_sat(49_000), script_pubkey: destination };

    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    let mut cache = SighashCache::new(&mut tx);
    let template_hash = cache.template_hash(0, None).expect("valid input index");
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from(template_hash), &keypair);

    let mut witness = Witness::new();
    witness.push(signature.serialize());
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());
    *cache.witness_mut(0).expect("valid input index") = witness;

    let signed_tx = cache.into_transaction();
    println!("template hash: {template_hash:x}");
    println!("signed transaction: {signed_tx:#?}");
}

fn bip448_rebindable_script() -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_TEMPLATEHASH)
        .push_opcode(OP_INTERNALKEY)
        .push_opcode(OP_CHECKSIGFROMSTACK)
        .into_script()
}

fn example_keypair() -> Keypair {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
    Keypair::from_secret_key(&secp, &secret_key)
}
