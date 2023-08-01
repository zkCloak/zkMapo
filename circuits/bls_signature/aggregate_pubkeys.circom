pragma circom 2.1.0;

include "../primitives/helpers/bn254_func.circom";
include "../primitives/curve_fp2.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/**
 * Aggregate publib keys based on a bit-map.
 * @param  b          The size of the set of public keys
 * @param  n          The number of bits to use per register
 * @param  k          The number of registers
 * @input  pubkeys    The b BN254 public keys in BigInt(n, k)
 * @input  bit_map The b-length bitmask for which pubkeys to include
 * @output out        \sum_{i=0}^{b-1} pubkeys[i] * bit_map[i] (over the BN254 curve)
 */
template AggregateG2s(b, n, k) {
    var p[50] = get_bn254_prime(n, k);

    signal input pubkeys[b][2][2][k];
    signal input bit_map[b];

    signal output out[2][2][k];

    component has_prev_nonzero[b];
    has_prev_nonzero[0] = OR();
    has_prev_nonzero[0].a <== 0;
    has_prev_nonzero[0].b <== bit_map[0];
    for (var i = 1; i < b; i++) {
        has_prev_nonzero[i] = OR();
        has_prev_nonzero[i].a <== has_prev_nonzero[i - 1].out;
        has_prev_nonzero[i].b <== bit_map[i];
    }

    signal partial[b][2][2][k];
    for (var idx = 0; idx < k; idx++) {
        for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
            for (var l = 0; l < 2; l++) {
                partial[0][x_or_y][l][idx] <== pubkeys[0][x_or_y][l][idx];
            }
        }
    }

    component adders[b - 1];
    signal intermed1[b - 1][2][2][k];
    signal intermed2[b - 1][2][2][k];
    for (var i = 1; i < b; i++) {
        adders[i - 1] = EllipticCurveAddUnequalFp2(n, k, p);
        for (var idx = 0; idx < k; idx++) {
            for (var l = 0; l < 2; l++) {
                for (var x_or_y = 0; x_or_y < 2; x_or_y++) {             
                    adders[i - 1].a[x_or_y][l][idx] <== partial[i - 1][x_or_y][l][idx];
                    adders[i - 1].b[x_or_y][l][idx] <== pubkeys[i][x_or_y][l][idx];
              }
            }
        }

        // partial[i] = has_prev_nonzero[i - 1] * ((1 - iszero[i]) * adders[i - 1].out + iszero[i] * partial[i - 1][0][idx])
        //              + (1 - has_prev_nonzero[i - 1]) * (1 - iszero[i]) * multiplexers[i]
        // TODO: refactor.
        for (var x_or_y = 0; x_or_y < 2; x_or_y++) {    
            for (var idx = 0; idx < k; idx++) {
                for (var l = 0; l < 2; l++) {
                    intermed1[i - 1][x_or_y][l][idx] <== (1-bit_map[i]) * (partial[i - 1][x_or_y][l][idx] - adders[i - 1].out[x_or_y][l][idx]) + adders[i - 1].out[x_or_y][l][idx];
                    intermed2[i - 1][x_or_y][l][idx] <== pubkeys[i][x_or_y][l][idx] - (1-bit_map[i]) * pubkeys[i][x_or_y][l][idx];
                    partial[i][x_or_y][l][idx] <== has_prev_nonzero[i - 1].out * (intermed1[i - 1][x_or_y][l][idx] - intermed2[i - 1][x_or_y][l][idx]) + intermed2[i - 1][x_or_y][l][idx];
                }
            }
        }
    }

    for (var x_or_y = 0; x_or_y < 2; x_or_y++) { 
        for (var idx = 0; idx < k; idx++) {
            for (var l = 0; l < 2; l++) {
                out[x_or_y][l][idx] <== partial[b - 1][x_or_y][l][idx];
            }
        }
    }
}

/*
 * Check the sum of weight >= 2/3*total_weights.
 * Check bit_map[m..b] are 0, since weights[m..b] is 0, that is checked in the contract. 
 * @param  b The size of the set of public keys
 * @input  bit_map the flag marks whether public key is included in aggregated public key
 * @input  weights    each weight of public key
 * @out isZero[b] each weight is 0 or not.
*/ 
template CheckWeights(b){
    signal input bit_map[b];
    signal input weights[b];
    signal output is_zero[b];

    // check is zero
    component is_w_zero[b];
    for(var i = 0; i < b; i++) {
        is_w_zero[i] = IsZero();
        is_w_zero[i].in <== weights[i];
    }

    // check weights[i] == 0 => bit_map[i]==0
    for(var i = 0; i < b; i++) {
        is_w_zero[i].out * bit_map[i] === 0;
    }

    // check bool 
    for(var i = 0; i < b; i++) {
        bit_map[i] * (1 - bit_map[i]) === 0;
    }

    signal sum[b];
    sum[0] <== bit_map[0] * weights[1];
    for (var i = 1; i < b; i++) {
        sum[i] <== sum[i-1] +  bit_map[i] * weights[i];
    }

    var total_weights;
    for (var i = 0; i < b; i++) {
        total_weights += weights[i];
    }

    // 32 bits
    component is_geq = GreaterEqThan(32);
    is_geq.in[0] <== sum[b-1] * 3;
    is_geq.in[1] <== total_weights * 2;

    is_geq.out === 1; 

    for(var i = 0; i < b; i++){
        is_zero[i] <== is_w_zero[i].out;
    }
}
