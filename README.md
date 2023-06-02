# zkMapo

This repository intends to implement Mapo's light client using zk-SNARKs. The POC is planned to be implemented using circom and groth16. Currently, the verification of BLS signatures based on circom has been implemented.

Mapo's BLS signature public keys are in G2, while the signatures are in G1. Therefore, hash-to-curve needs to be performed on G1. The circuit implementation of HashToG1 is based on the Solidity code found at https://github.com/mapprotocol/map-contracts/blob/main/mapclients/eth/contracts/bls/BGLS.sol. The only difference is that to reduce the size of the circuit, the two hashToBase functions in the Solidity code (each of which is essentially two keccak256 hashes) are moved outside of the circuit.

## Benchmark

|                      | HashToG1    | VerifySignature |
| -------------------- | :---------: | --------------  |
| Constraints          | 2.75M       | 15.69M          |
| Compile              | 94s         | ~ 1.9h          |
| Generate witness(js) | 30s         | 380s            |
| Prove(js)            | 96s         | 9min            |
| Prove(rapidsnark)    |  8s         |  36s            |
| Verify(js)           | 0.57s       | 0.58s           |