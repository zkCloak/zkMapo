pragma circom 2.1.0;

include "../primitives/bigint.circom";
include "../primitives/fp.circom";
include "../primitives/curve.circom";
include "../primitives/helpers/bn254_func.circom";
include "../primitives/helpers/bigint_func.circom";

// `in` is [hashToBase(message, 0x00, 0x01), hashToBase(message, 0x02, 0x03)]
// `out` is point in G1
// The implementation is almost same as `hashToG1` in https://github.com/mapprotocol/map-contracts/blob/main/mapclients/eth/contracts/bls/BGLS.sol
template HashToG1(n, k){
    signal input in[2][k];
    signal output out[2][k];

    var p[50] = get_bn254_prime(n, k);
    component h0 = BaseToG1(n,k);
    component h1 = BaseToG1(n,k);
    for(var idx = 0; idx < k; idx++) {
        h0.in[idx] <== in[0][idx];
        h1.in[idx] <== in[1][idx];
    }
    component r = EllipticCurveAdd(n, k, 0, 3, p);
    for (var i = 0; i < 2; i++) 
        for (var idx = 0; idx < k; idx++) {
            r.a[i][idx] <== h0.out[i][idx];
            r.b[i][idx] <== h1.out[i][idx];
        }
    r.aIsInfinity <== 0;
    r.bIsInfinity <== 0;
    
    for(var i=0; i<2; i++)
        for(var idx=0; idx<k; idx++)
            out[i][idx] <== r.out[i][idx];
    r.isInfinity === 0; 
}

template BaseToG1(n,k) {
    signal input in[k]; // t
    signal output out[2][k];
    var b = 3;
    var p[50] = get_bn254_prime(n, k);

    // compute t^2 
    component ap1 = FpMultiply(n, k, p);
    for(var i=0; i<k; i++){
        ap1.a[i] <== in[i];
        ap1.b[i] <== in[i];
    }
    // compute t^2 * (t^2 + 4)
    component alpha_inv = FpMultiply(n, k, p);
    alpha_inv.a[0] <== ap1.out[0];
    alpha_inv.b[0] <== ap1.out[0] + 4; // 4 = 1+b
    for(var i=1; i<k; i++){
        alpha_inv.a[i] <== ap1.out[i];
        alpha_inv.b[i] <== ap1.out[i];
    }
    // alpha_inv^{-1}
    component alpha = BigModInv(n,k);
    for(var i=0; i<k; i++){
        alpha.in[i] <== alpha_inv.out[i];
        alpha.p[i] <== p[i]; // 1+b
    }
    // tmp = (t^2 + 4)^3
    component tmp1 = FpMultiply(n, k, p);
    tmp1.a[0] <== ap1.out[0] + 4;
    tmp1.b[0] <== ap1.out[0] + 4;
    for(var i=1; i<k; i++){
        tmp1.a[i] <== ap1.out[i];
        tmp1.b[i] <== ap1.out[i];
    }
    component tmp = FpMultiply(n, k, p);
    tmp.a[0] <== tmp1.out[0];
    tmp.b[0] <== ap1.out[0] + 4;
    for(var i=1; i<k; i++){
        tmp.a[i] <== tmp1.out[i];
        tmp.b[i] <== ap1.out[i];
    }

    // ap12 = ap1^2 = t^4
    component ap12 = FpMultiply(n, k, p);
    for(var i=0; i<k; i++){
        ap12.a[i] <== ap1.out[i];
        ap12.b[i] <== ap1.out[i];
    }
    // x1 = h1 - h2 * t^4 * alpha
    component x1_tmp = FpMultiply(n, k, p);
    for(var i=0; i<k; i++){
        x1_tmp.a[i] <== ap12.out[i];
        x1_tmp.b[i] <== alpha.out[i];
    }
    var h1[50];// (-1 + sqrt(-3))/2
    var h2[50];// sqrt(-3)
    var h3[50];// 1/3
    var pMinus1Over2[50]; // (p - 1)/2
    var pPlus1Over4Bits[252] = [0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1];
    assert( (n==51 && k==5) || (n==43 && k==6) );
    if( n==51 && k==5 ){
        h1 = [922702722367486, 1747791500667628, 934785460717967, 193025402704, 0];
        h2 = [1845405444734973, 1243783187650008, 1869570921435935, 386050805408, 0];
        h3 = [102686499492741, 408326045243992, 1129844010735900, 15290532489088, 567545290820796];
        pMinus1Over2 = [77014874619555, 306244533932994, 847383008051925, 11467899366816, 425658968115597];
    }
    if( n==43 && k==6 ){
        h1 = [7909048057854, 3760410258536, 3658398811827, 6491044726230, 368166, 0];
        h2 = [7022003093501, 7520820517073, 7316797623654, 4185996430252, 736333, 0];
        h3 =[5929476248453, 7494199564299, 7599292165739, 2093804974793, 5205529527128, 277121724033];
        pMinus1Over2 = [6646130441891, 7819672928776, 3500445868752, 1570353731095, 1705123889794, 207841293025];
    }

    component x1_tmp1 = FpMultiply(n, k, p);
    for(var i=0; i<k; i++){
        x1_tmp1.a[i] <== x1_tmp.out[i];
        x1_tmp1.b[i] <== h2[i];
    }
    component x1 = FpSubtract(n, k, p);
    for(var i=0; i<k; i++){
        x1.a[i] <== h1[i];
        x1.b[i] <== x1_tmp1.out[i];
    }

    // x2 == -1 - x1
    component x2 = FpNegate(n, k, p);
    x2.in[0] <== x1.out[0] + 1;
    for(var i=1; i<k; i++){
        x2.in[i] <== x1.out[i];
    }

    //  x3 == 1 - h3*tmp*alpha
    component x3_tmp1 = FpMultiply(n, k, p);
    for(var i=0; i<k; i++){
        x3_tmp1.a[i] <== tmp.out[i];
        x3_tmp1.b[i] <== h3[i];
    }
    component x3_tmp2 = FpMultiply(n, k, p);
    for(var i=0; i<k; i++){
        x3_tmp2.a[i] <== x3_tmp1.out[i];
        x3_tmp2.b[i] <== alpha.out[i];
    }
    component x3 = FpNegate(n, k, p);
    x3.in[0] <== x3_tmp2.out[0] - 1;
    for(var i=1; i<k; i++){
        x3.in[i] <== x3_tmp2.out[i];
    }

    // g(x) = x^3 + 3
    component gx1 = BN254Function(n, k, 3, p);
    component gx2 = BN254Function(n, k, 3, p);
    component gx3 = BN254Function(n, k, 3, p);
    for(var j=0; j < k; j++) {
        gx1.in[j] <== x1.out[j];
        gx2.in[j] <== x2.out[j];
        gx3.in[j] <== x3.out[j];
    }
    component gx1_root = Sqrt(n, k, p, pPlus1Over4Bits);
    component gx2_root = Sqrt(n, k, p, pPlus1Over4Bits);
    component gx3_root = Sqrt(n, k, p, pPlus1Over4Bits);
    for(var j=0; j < k; j++) {
        gx1_root.in[j] <== gx1.out[j];
        gx2_root.in[j] <== gx2.out[j];
        gx3_root.in[j] <== gx3.out[j];
    }
    // if gx1 is QR, then we choose x1
    // else if gx2 is QR, then we choose x2
    // else choose x3
    signal is_x1;
    signal is_x2;
    signal is_x3;
    is_x1 <== gx1_root.isSquare;
    is_x2 <== (1 - is_x1) * gx2_root.isSquare;
    signal is_not_x1_x2;
    is_not_x1_x2 <== (1 - is_x1) * (1 - is_x2);
    is_x3 <== is_not_x1_x2 * gx3_root.isSquare;
    is_x1 + is_x2 + is_x3 === 1;

    signal outx_tmp1[k];
    signal outx_tmp2[k];
    for(var idx = 0; idx < k; idx++) {
        outx_tmp1[idx] <== is_x1 * x1.out[idx];
        outx_tmp2[idx] <== is_x2 * x2.out[idx];
        out[0][idx] <== outx_tmp1[idx] + outx_tmp2[idx] + is_x3 * x3.out[idx];
    }

    signal outy_tmp1[k];
    signal outy_tmp2[k];
    signal y_tmp[k];
    for(var idx = 0; idx < k; idx++) {
        outy_tmp1[idx] <== is_x1 * gx1_root.out[idx];
        outy_tmp2[idx] <== is_x2 * gx2_root.out[idx];
        y_tmp[idx] <== outy_tmp1[idx] + outy_tmp2[idx] + is_x3 * gx3_root.out[idx];
    }
    // choose y on base of the sign of `in`
    // if in <= (p-1)/2, y = y
    // else y = p-y
    component sign_in = BigLessThan(n,k);
    for(var idx = 0; idx < k; idx++) {
        sign_in.a[idx] <== pMinus1Over2[idx];
        sign_in.b[idx] <== in[idx];
    }
    // calculate p-y
    component minus_y = FpNegate(n, k, p);
    for(var i=0; i<k;i++) {
        minus_y.in[i] <== y_tmp[i];
    }
    for(var i=0; i<k; i++) {
        out[1][i] <== y_tmp[i] + sign_in.out * (minus_y.out[i] - y_tmp[i]);
    }
    // check on curve
    component is_point_on_curve = PointOnCurve(n, k, 0, b, p);
    for(var i = 0; i < 2; i++)
        for(var j = 0; j < k; j++) {
            is_point_on_curve.in[i][j] <== out[i][j];
        }
}

// input in, output its square root if it has.
template Sqrt(n, k, p, pPlus1Over4Bits) {
    signal input in[k];
    signal output isSquare;
    signal output out[k];

    var weight = 0;
    for(var i=0; i<252;i++){
        weight = weight + pPlus1Over4Bits[i];
    }

    signal b[252][k];
    signal prod[weight+1][k];
    for(var i=0; i<k; i++){
        b[0][i] <== in[i];
        if (i == 0){
            prod[0][i] <== 1;
        } else{
            prod[0][i] <== 0;
        }
    }
    // b = in, prod = 1
    // for i in range(252):
    //   if bits[i] == 1:
    //      prod = prod * b
    //   b = b * b
    component tmp1[weight];
    component tmp2[251];
    var idx = 0;
    for(var i=0; i<252; i++){
        if (pPlus1Over4Bits[i] == 1){
            tmp1[idx] = FpMultiply(n,k,p);
            for(var j=0; j<k; j++){
                tmp1[idx].a[j] <== prod[idx][j];
                tmp1[idx].b[j] <== b[i][j];
            }
            idx++;
            for(var j=0; j<k; j++) {
                prod[idx][j] <== tmp1[idx-1].out[j];
            }
        }
        if(i < 251) {
            tmp2[i] = FpMultiply(n,k,p);
            for(var j=0; j<k; j++){
                tmp2[i].a[j] <== b[i][j];
                tmp2[i].b[j] <== b[i][j];
            }
            for(var j=0; j<k; j++) {
                b[i+1][j] <== tmp2[i].out[j];
            }
        }
    }
    assert(idx == weight);
    for(var i=0; i<k; i++) {
        out[i] <== prod[weight][i];
    }

    // Now check if `out` is the sqrt of `in`
    component square = FpMultiply(n,k,p);
    for(var i=0; i<k; i++){
        square.a[i] <== out[i];
        square.b[i] <== out[i];
    }
    component is_equal = FpIsEqual(n,k,p);
    for(var i=0; i<k; i++){
        is_equal.in[0][i] <== square.out[i];
        is_equal.in[1][i] <== in[i];
    }
    isSquare <== is_equal.out;
}