# ark_groth16 on bls12 381 proof verification with blst

This is a proof of concept on how to use [blst](https://github.com/supranational/blst) to verify arkworks groth16 proofs on bls12 381.

The fastest way to verify a proof is by using blst::pairing with paring_blst.as_fp12().final_exp() for verification see [blst_poc.rs](https://github.com/ananas-block/).

## blst functions and datatypes used in onchain part
- Pairing (including methods: new, raw_aggregate, commit, as_fp12)
- blst_fp12 (including methods)
- blst_p1
- blst_p1_affine
- blst_p1_mult
- blst_p1_add
- blst_p1_to_affine
- blst_p1_from_affine
- blst_p1_affine_serialize
- blst_p1_deserialize
- blst_p2
- blst_p2_affine
- blst_p2_affine_serialize
- blst_p2_deserialize
- blst_fp
- blst_fp_from_lendian
- blst_fp2
- blst_fp6
- blst_fp12

## helper functions to parse blst datatypes
- parse_fp2_from_bytes_blst
- parse_fp6_from_bytes_blst
- parse_fp12_from_bytes_blst

## Neptune Poseidon hash
[neptune_poseidon_hash.rs]() implements an example of poseidon hashes of up to 5 inputs with the [neptune library](https://github.com/filecoin-project/neptune).


For reference, the filecoin team has created [blstrs](https://github.com/filecoin-project/blstrs) a rust wrapper library around blst rust bindings which is simpler to use.
