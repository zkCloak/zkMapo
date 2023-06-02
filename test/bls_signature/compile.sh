start=`date +%s`
circom signature.circom --r1cs --wasm --sym --c --output signature
end=`date +%s`
echo "DONE ($((end-start))s)"
