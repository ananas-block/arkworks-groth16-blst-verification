#![allow(unused)]
use ark_groth16_verification_blst::blstrs_poc::blstrs_test;
use ark_groth16_verification_blst::blst_poc::groth_16_verification_with_blst;
use ark_groth16_verification_blst::neptune_poseidon_hash::poseidon_neptun;

fn main() {
    groth_16_verification_with_blst();
    //blstrs_test();
    // poseidon_neptun();
}
