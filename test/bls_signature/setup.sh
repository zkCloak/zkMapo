#!/bin/bash
# snarkjs groth16 setup signature/signature.r1cs pot25_final.ptau signature_0.zkey -v
#snarkjs zkey contribute signature_0.zkey signature_1.zkey --name="sfa" -v
#snarkjs zkey export verificationkey signature_1.zkey verification_key.json
# CIRCUIT_NAME=signature
# PHASE1 = 
# echo "****GENERATING ZKEY 0****"
# start=`date +%s`
# node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=128 --initial-heap-size=2048000 --expose-gc /usr/local/lib/node_modules/snarkjs/cli.js zkey new "$CIRCUIT_NAME"/"$CIRCUIT_NAME".r1cs /data/repos/keys/pot25_final.ptau "$CIRCUIT_NAME"_0.zkey -v
# end=`date +%s`
# echo "DONE ($((end-start))s)"



