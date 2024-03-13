pragma circom 2.1.0;

include "../primitives/fp2.circom";
include "../primitives/subgroup_check.circom";
include "../primitives/final_exp.circom";
include "../primitives/pairing.circom";
include "../primitives/sha256/sha256.circom";
include "hash_to_G1.circom";
include "aggregate_pubkeys.circom";

// Inputs:
//   - pubkeys in G2
//   - weights each weight of public key 
//   - bit_map The b-length bitmask for which pubkeys to include
//   - hash as element of E(Fq),
//     - hash[0][]: {keccak256(0x00,msg) || keccak256(0x01,msg)} mod p
//     - hash[1][]: {keccak256(0x02,msg) || keccak256(0x03,msg)} mod p
//   - signature in G1
template VerifyAggregatedSignature(b, n, k){
    signal input pubkeys[b][2][2][k];
    signal input weights[b];
    signal input bit_map[b];

    signal input signature[2][k];
    signal input hash[2][k]; 
    
    signal input commitment;
    
    // check threshold
    component check_weight = CheckWeights(b);
    for (var i = 0; i < b; i++) {
        check_weight.bit_map[i] <== bit_map[i];
        check_weight.weights[i] <== weights[i];
    }

    // Aggregate public keys
    component aggregated_pubkey = AggregateG2s(b,n,k);
    for (var cnt = 0; cnt < b; cnt++){
        aggregated_pubkey.bit_map[cnt] <== bit_map[cnt];

        for (var i = 0; i < 2; i++)
            for (var j = 0; j < 2; j++)
                for (var idx = 0; idx < k; idx++) {
                    aggregated_pubkey.pubkeys[cnt][i][j][idx] <== pubkeys[cnt][i][j][idx];
                }
    }

    // verify signature
    component check_sig = VerifySignature(n,k);
    for (var i = 0; i < 2; i++)
        for (var j = 0; j < k; j++) {
            check_sig.pubkey[0][i][j] <== aggregated_pubkey.out[0][i][j];
            check_sig.pubkey[1][i][j] <== aggregated_pubkey.out[1][i][j];
            check_sig.signature[i][j] <== signature[i][j];
            check_sig.hash[i][j] <== hash[i][j];
        }

    // compute validator commitment 
    // sha256(pk[0].x.c1, pk[0].x.c0, pk[0].y.c1, pk[0].y.c0, pk[0].weight,...,pk[b-1].x, pk[b-1].y, pk[b-1].weight)
    // if weights[i] == 0, we select {pk[0].x.c1=0, pk[0].x.c0=0, pk[0].y.c1=0, pk[0].y.c0=0} to hash.
    // c0,c1 256-bit BE, weight 256-bit BE
    // Input of sha256 (256 * 5 * b) bits
    component xybits[4*b];
    for(var i = 0; i < b; i++)
        for(var x_or_y = 0; x_or_y < 2; x_or_y++)
            for(var c0_or_c1 = 0; c0_or_c1 < 2; c0_or_c1++){
                xybits[i*4 + x_or_y*2 + c0_or_c1] = BigToBits(n,k);
                    for(var j = 0; j < k; j++) {
                        xybits[i*4 + x_or_y*2 + c0_or_c1].in[j] <== (1 - check_weight.is_zero[i]) * pubkeys[i][x_or_y][c0_or_c1][j];
                    }
            }

    // LE bits, and convert to BE bits later.
    component wbits[b];
    for(var i = 0; i < b; i++) {
        wbits[i] = NumTo256Bits(32);
        wbits[i].in <== weights[i]; 
    }

    // Now it's time to sha256
    component validators_commitment = Sha256(b*256*5);
    for(var i = 0; i < b; i++) {
        for(var idx = 0; idx < 256; idx++){// {x.c1 || x.c0 || y.c1 || y.c0}
            validators_commitment.in[1280*i + idx] <== xybits[i*4+1].out[idx];
            validators_commitment.in[1280*i + 256 + idx] <== xybits[i*4].out[idx];
            validators_commitment.in[1280*i + 512 + idx] <== xybits[i*4+3].out[idx];
            validators_commitment.in[1280*i + 768 + idx] <== xybits[i*4+2].out[idx];
            validators_commitment.in[1280*i + 1024 + idx] <== wbits[i].out[idx];
        }
    }

    component hash_bits[2];
    for(var i = 0; i < 2; i++){
        hash_bits[i] = BigToBits(n,k);
        for(var j = 0; j < k; j++) {
            hash_bits[i].in[j] <== hash[i][j];
        }
    }

    // hash_cm = sha256(t0, t1)
    component hash_cm = Sha256(512);
    for(var i = 0; i < 2; i++)
        for(var j = 0; j < 256; j++)
            hash_cm.in[i*256 + j] <== hash_bits[i].out[j];

     // final_commitment = sha256(validators_commitment, hash_cm)
    component final_commitment = Sha256(512);
    for(var i = 0; i < 256; i++){
        final_commitment.in[i] <== validators_commitment.out[i];
        final_commitment.in[256 + i] <== hash_cm.out[i];
    }
    // Finally, we will remove the most significant 3 bits
    // commitment.out[3..]
    component out = Bits2Num(253);
    for(var i = 0; i < 253; i++) {
        out.in[i] <== final_commitment.out[255-i];
    }

    commitment === out.out;
}

// Inputs:
//   - pubkey in G2
//   - hash as element of E(Fq),
//     - hash[0][]: {keccak256(0x00,msg) || keccak256(0x01,msg)} mod p
//     - hash[1][]: {keccak256(0x02,msg) || keccak256(0x03,msg)} mod p
//   - signature in G1
template VerifySignature(n, k){
    signal input pubkey[2][2][k];
    signal input signature[2][k];
    signal input hash[2][k]; 
     
    var q[50] = get_bn254_prime(n, k);

    component lt[8];
    for(var i=0; i<8; i++){
        lt[i] = BigLessThan(n, k);
        for(var idx=0; idx<k; idx++)
            lt[i].b[idx] <== q[idx];
    }
    for(var idx=0; idx<k; idx++){
        lt[0].a[idx] <== pubkey[0][0][idx];
        lt[1].a[idx] <== pubkey[0][1][idx];
        lt[2].a[idx] <== pubkey[1][0][idx];
        lt[3].a[idx] <== pubkey[1][1][idx];
        lt[4].a[idx] <== signature[0][idx];
        lt[5].a[idx] <== signature[1][idx];
        lt[6].a[idx] <== hash[0][idx];
        lt[7].a[idx] <== hash[1][idx];
    }
    var lt_out = 0;
    for(var i = 0; i < 8; i++){
        lt_out += lt[i].out;
    }
    lt_out === 8;  

    component check[4]; 
    for(var i=0; i<4; i++)
        check[i] = RangeCheck2D(n, k); 
    for(var i=0; i<2; i++)for(var idx=0; idx<k; idx++){
        check[0].in[i][idx] <== pubkey[0][i][idx];
        check[1].in[i][idx] <== pubkey[1][i][idx];
        check[2].in[i][idx] <== signature[i][idx];
        check[3].in[i][idx] <== hash[i][idx];
    }
    
    component pubkey_valid = SubgroupCheckG2(n, k);
    for(var i=0; i<2; i++)for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++)
        pubkey_valid.in[i][j][idx] <== pubkey[i][j][idx];

    component signature_valid = SubgroupCheckG1(n, k);
    for(var i=0; i<2; i++)for(var idx=0; idx<k; idx++)
        signature_valid.in[i][idx] <== signature[i][idx];

    component Hm = HashToG1(n, k);
    for(var i=0; i<2; i++)for(var idx=0; idx<k; idx++)
        Hm.in[i][idx] <== hash[i][idx];
    
    component verify = VerifySignatureCore(n, k);

    for(var i=0; i<2; i++)for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++)
        verify.pubkey[i][j][idx] <== pubkey[i][j][idx];
    for(var i=0; i<2; i++)for(var idx=0; idx<k; idx++){
        verify.signature[i][idx] <== signature[i][idx];
        verify.Hm[i][idx] <== Hm.out[i][idx]; 
    }

    verify.out === 1;
}


// Input: pubkey in G_2 
//        signature in G_1
// Output: out = 1 if valid signature, else = 0
// Verifies that e(signature,g2) = e(H(m), pubkey)
template VerifySignatureCore(n, k){
    signal input pubkey[2][2][k];
    signal input signature[2][k];
    signal input Hm[2][k];
    signal output out;

    var p[50] = get_bn254_prime(n, k);
    var g2[2][2][50] = get_generator_G2(n, k); 

    signal neg_hm[2][k];
    component neg = FpNegate(n, k, p); 
    for(var idx=0; idx<k; idx++)
        neg.in[idx] <== Hm[1][idx];
    for(var idx=0; idx<k; idx++){
        neg_hm[0][idx] <== Hm[0][idx];
        neg_hm[1][idx] <== neg.out[idx];
    }

    component pairing = OptimalAtePairingMulti(2, n, k, p);
    
    for(var i=0; i<2; i++)for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++){
        pairing.P[0][i][j][idx] <== g2[i][j][idx];
        pairing.P[1][i][j][idx] <== pubkey[i][j][idx];
    }
    for(var i=0; i<2; i++)for(var idx=0; idx<k; idx++){
        pairing.Q[0][i][idx] <== signature[i][idx];
        pairing.Q[1][i][idx] <== neg_hm[i][idx];
    }

    component is_valid[6][2][k];
    var total = 12*k;
    for(var i=0; i<6; i++)for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++){
        is_valid[i][j][idx] = IsZero(); 
        if(i==0 && j==0 && idx==0)
            is_valid[i][j][idx].in <== pairing.out[i][j][idx] - 1;
        else
            is_valid[i][j][idx].in <== pairing.out[i][j][idx];
        total -= is_valid[i][j][idx].out; 
    }
    component valid = IsZero(); 
    valid.in <== total;
    out <== valid.out;
}

// n-bit number to 256 bits (BE)
template NumTo256Bits(n){
    signal input in;
    signal output out[256];

    component bits = Num2Bits(n);
    bits.in <== in;
    for(var i = 0; i < 256 - n; i++) {
        out[i] <== 0;
    }
    for(var i = 0;i < n; i++) {
        out[256 - n + i] <== bits.out[n-1-i];
    }
}