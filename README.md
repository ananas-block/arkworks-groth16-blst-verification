#ark_groth16 on bls12 381 proof verification with blst

This is a proof of concept on how to use [blst](https://github.com/supranational/blst) to verify arkworks groth16 proofs on bls12 381.

The filecoin team has created [blstrs](https://github.com/filecoin-project/blstrs) a rust wrapper library around blst rust bindings which is simpler to use.

##blst functions and datatypes used in onchain part
- blst_p1_mult
- blst_p1_to_affine
- blst_p1_add_or_double_affine
- blst_p1_affine
- blst_p2_affine
- blst_miller_loop
- blst_fp12 (including methods)
- blst_fp12.mul_assign()
- blst_fp12.final_exp()
- read_fp_blst

##custom helper functions to parse blst datatypes
- read_fp_blst (wrapper around read_fp_blst)
- parse_fp2_from_bytes_blst
- get_p1_affine
- get_p2_affine
