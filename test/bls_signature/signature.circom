pragma circom 2.1.0;

include "../../circuits/bls_signature/signature.circom";

component main { public [ commitment] } = VerifyAggregatedSignature(8, 43, 6);

