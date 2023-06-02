pragma circom 2.1.0;

include "../../circuits/bls_signature/signature.circom";

component main { public [ pubkey, hash ] } = VerifySignature(43, 6);

