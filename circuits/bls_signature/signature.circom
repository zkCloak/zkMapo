pragma circom 2.1.0;

include "../primitives/fp2.circom";
include "../primitives/subgroup_check.circom";
include "../primitives/final_exp.circom";
include "../primitives/pairing.circom";
include "hash_to_G1.circom";
include "../primitives/helpers/bn254_func.circom";

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

