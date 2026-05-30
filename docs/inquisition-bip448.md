# Bitcoin Inquisition BIP448 Helpers

This branch adds local wallet/client helpers for Bitcoin Inquisition signet scripts that use the
BIP448 opcode bundle:

- `OP_TEMPLATEHASH` (`0xce`, BIP446)
- `OP_INTERNALKEY` (`0xcb`, BIP349)
- `OP_CHECKSIGFROMSTACK` (`0xcc`, BIP348)

The support is intentionally non-consensus. It lets applications construct Taproot scripts,
compute BIP446 `TemplateHash` values, and sign those hashes with raw BIP340 signatures for
`OP_CHECKSIGFROMSTACK`. It does not add a script interpreter, activation logic, mempool policy, or
consensus validation.

## Scope

Use these helpers for constructing and signing transactions intended for Bitcoin Inquisition signet.
Do not use them as evidence that a transaction is valid under Bitcoin mainnet consensus or under an
Inquisition deployment.

The default opcode classifier remains current Bitcoin behavior: in `ClassifyContext::TapScript`,
the bytes `0xcb`, `0xcc`, and `0xce` still classify as `SuccessOp`. The named opcode aliases are for
script construction only.

## TemplateHash

`SighashCache::template_hash(input_index, annex)` computes the BIP446 tagged hash using the tag
`TemplateHash`.

The preimage commits to:

- transaction version
- transaction lock time
- all input sequences
- all outputs
- this input index
- this input's annex presence and annex hash, when present

The preimage does not commit to prevouts, spent amounts, spent script pubkeys, scriptSigs, or other
inputs' annexes.

See:

- `bitcoin/examples/inquisition_bip448_script.rs`
- `bitcoin/examples/inquisition_bip448_templatehash.rs`
