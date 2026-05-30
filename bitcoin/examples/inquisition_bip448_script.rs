// SPDX-License-Identifier: CC0-1.0

//! Build a Bitcoin Inquisition/BIP448 Taproot script output.
//!
//! This is construction-only support. Current Bitcoin consensus still treats these bytes as
//! `OP_SUCCESSx`; Bitcoin Inquisition signet gives them the BIP448 meanings.

use bitcoin::opcodes::all::{OP_CHECKSIGFROMSTACK, OP_INTERNALKEY, OP_TEMPLATEHASH};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::ScriptBuf;
use hex::DisplayHex;

fn main() {
    let secp = Secp256k1::new();
    let keypair = example_keypair();
    let internal_key = keypair.x_only_public_key().0;

    let script = bip448_rebindable_script();
    assert_eq!(script.as_bytes(), &[0xce, 0xcb, 0xcc]);

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("valid taproot tree")
        .finalize(&secp, internal_key)
        .expect("finalizable taproot tree");

    let script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    let control_block =
        spend_info.control_block(&(script, LeafVersion::TapScript)).expect("script is in tree");

    println!("scriptPubKey: {script_pubkey:x}");
    println!("control block: {:x}", control_block.serialize().as_hex());
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
