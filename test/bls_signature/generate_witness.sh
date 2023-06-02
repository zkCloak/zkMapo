start=`date +%s`
node signature/signature_js/generate_witness.js signature/signature_js/signature.wasm input.json witness.wtns
end=`date +%s`
echo "DONE ($((end-start))s)"
