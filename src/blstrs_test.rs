#![allow(unused)]
use crate::parsers::*;
use crate::arkworks_circuit::*;
use blst::blst_miller_loop;
use blst::*;
use blstrs::*;

use pairing::MultiMillerLoop;
use pairing::Engine;
// For randomness (during paramgen and proof generation)
use ark_std::rand::Rng;

// For benchmarking
use std::time::{Duration, Instant};

// Bring in some tools for using pairing-friendly curves
// We're going to use the Bls12-377 pairing-friendly elliptic curve.
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff;
use ark_ff::Field;
use ark_std::test_rng;
use ark_groth16::prepare_inputs;
use ark_ec::ProjectiveCurve;

use ark_ff::Fp384;
use ark_std::UniformRand;
use ark_ff::bytes::{FromBytes, ToBytes};
use std::convert::{TryFrom, TryInto};
use ark_std::One;
// We'll use these interfaces to construct our circuit.
use ark_relations::{
    lc, ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_ec::models::bls12::g1::G1Prepared;
use ark_ec::models::bls12::g2::G2Prepared;

use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use std::ops::MulAssign;
use pairing::MillerLoopResult;
 use std::ops::Mul;

pub fn blstrs_test() {

    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    // Generate the MiMC round constants
    let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

    println!("Creating parameters...");

    // Create parameters for our circuit
    let params = {
        let c = MiMCDemo::<Fr> {
            xl: None,
            xr: None,
            constants: &constants,
        };

        generate_random_parameters::<Bls12_381, _, _>(c, rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    // Just a place to put the proof data, so we can
    // benchmark deserialization.
    // let mut proof_vec = vec![];

    // Generate a random preimage and compute the image
    let xl = rng.gen();
    let xr = rng.gen();
    let image = mimc(xl, xr, &constants);

    // proof_vec.truncate(0);


        // Create an instance of our circuit (with the
        // witness)
        let c = MiMCDemo {
            xl: Some(xl),
            xr: Some(xr),
            constants: &constants,
        };



        // Create a groth16 proof with our parameters.
        let proof = create_random_proof(c, &params, rng).unwrap();
        assert!(verify_proof(&pvk, &proof, &[image]).unwrap());
        println!("success");
        let prepared_inputs = prepare_inputs(&pvk, &[image]).unwrap();
        println!(" proof.a {:?}", proof.a);
        let mut input_bytes = vec![];
        <Fr as ToBytes>::write(
            &image,
            &mut input_bytes,
        )
        .unwrap();
        let mut gamma_abc_g1_bytes_0 = vec![0u8;96];
        let mut gamma_abc_g1_bytes_1 = vec![0u8;96];

        parse_proof_a_or_c_to_bytes(params.vk.gamma_abc_g1[0], &mut gamma_abc_g1_bytes_0);
        parse_proof_a_or_c_to_bytes(params.vk.gamma_abc_g1[1], &mut gamma_abc_g1_bytes_1);
        println!("proof_b_g2_bytes: {:?}", gamma_abc_g1_bytes_0     );

        let gamma_abc_g1_blst_1 = blst_p1_affine {
            x: read_fp_blst(&gamma_abc_g1_bytes_1[0..48]),
            y: read_fp_blst(&gamma_abc_g1_bytes_1[48..96])
        };
        let mut p2_bytes_be = [0u8;96];
        unsafe {
            let blst_fp_ptr: *const blst::blst_p1_affine = &gamma_abc_g1_blst_1;

            blst_p1_affine_serialize(
                p2_bytes_be.as_mut_ptr(),
                blst_fp_ptr
            );
        };
        let mut g1_affine_0 = G1Affine::from_uncompressed(&p2_bytes_be).unwrap();

        let bytes_u64 = u64s_from_bytes(&input_bytes.clone().try_into().unwrap());
        let mut input_bytes_blst = blst_fr::default();
        unsafe { blst_fr_from_uint64(&mut input_bytes_blst, &bytes_u64[0]) };

        // println!("bytes_u64: {:?}",<blstrs::Scalar as From<blst_fr>>::from(input_bytes_blst));
        // Scalar is correct
        println!("g1_affine_0: {:?}",g1_affine_0);

        g1_affine_0.mul_assign(&<blstrs::Scalar as From<blst_fr>>::from(input_bytes_blst));
        println!("{:?}", g1_affine_0);
        panic!();
        let proof_a_g1 = proof.a;//(prepared_inputs).into_affine();

        let mut proof_a_g1_bytes = vec![0u8;96];
        parse_proof_a_or_c_to_bytes(proof_a_g1, &mut proof_a_g1_bytes);
        println!("proof.a.into(): {:?}",proof_a_g1_bytes);

        let proof_b_g2 = proof.b;//params.vk.gamma_g2;

        let mut proof_b_g2_bytes = vec![0u8;192];
        parse_proof_b_to_bytes(proof_b_g2, &mut proof_b_g2_bytes);
        println!("proof.b.into(): {:?}", proof_b_g2_bytes);

        /*
        let proof_prep_g1 = (prepared_inputs).into_affine();
        let mut proof_prep_g1_bytes = vec![0u8;96];
            proof_prep_g1_bytes = parse_proof_a_or_c_to_bytes(proof_prep_g1);

        let proof_gamma_g2 = params.vk.gamma_g2;
        let mut proof_gamma_g2_bytes = vec![0u8;192];
        parse_proof_b_to_bytes(proof_gamma_g2, &mut proof_gamma_g2_bytes);

        let proof_c_g1 = proof.c;
        let mut proof_c_g1_bytes = vec![0u8;96];
        proof_c_g1_bytes = parse_proof_a_or_c_to_bytes(proof_c_g1);

        let proof_delta_g2 = params.vk.delta_g2;
        let mut proof_delta_g2_bytes = vec![0u8;192];
        parse_proof_b_to_bytes(proof_delta_g2, &mut proof_delta_g2_bytes);
        */
        let miller_output =
            <ark_ec::models::bls12::Bls12::<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::miller_loop(
                [
                    (proof.a.into(), proof.b.into()),/*
                    (
                        (prepared_inputs).into_affine().into(),
                        pvk.gamma_g2_neg_pc.clone(),
                    ),
                    (proof.c.into(), pvk.delta_g2_neg_pc.clone()),*/
                ]
                .iter(),
        );
        let res_origin = <ark_ec::models::bls12::Bls12::<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::final_exponentiation(&miller_output).unwrap();

        let pairing_output = <ark_ec::models::bls12::Bls12::<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::pairing(proof.a, proof.b);
        assert_eq!(pairing_output, res_origin, "pairing vs manual");
        let blstrs : Bls12;
        println!("proof_a_g1_bytes: {:?}", proof_a_g1_bytes);
        // let a_g1 = G1Affine( blst_p1_affine {
        //     x: read_fp_blst(&proof_a_g1_bytes[0..48]),
        //     y: read_fp_blst(&proof_a_g1_bytes[48..96]),
        // });
        let mut out = blst_p1_affine::default();
        let mut fp_bytes_be = [0u8;96];
        //println!("bytes_le: {:?}", fp_bytes_le);

        // for (i, elem) in proof_a_g1_bytes.iter().rev().enumerate(){
        //     fp_bytes_be[i] = *elem;
        // }
        let manual_g1 = blst_p1_affine {
            x: read_fp_blst(&proof_a_g1_bytes[0..48]),
            y: read_fp_blst(&proof_a_g1_bytes[48..96])
        };
        unsafe {
            let blst_fp_ptr: *const blst::blst_p1_affine = &manual_g1;

            blst_p1_affine_serialize(
                fp_bytes_be.as_mut_ptr(),
                blst_fp_ptr
            );
        };
        println!("fp_bytes_be {:?}", fp_bytes_be);
        let mut out = blst_p1_affine::default();
        // unsafe {
        //    blst_p1_deserialize(&mut out, fp_bytes_be.as_ptr());
        // }
        println!("proof.a {}",proof.a);
        let a = G1Affine::from_uncompressed(&fp_bytes_be).unwrap();
        println!("proof_a_g1_bytes: {:?}", a);

        println!("proof_b_g2_bytes: {:?}", proof_b_g2_bytes     );
        let blst_proof_b = blst_p2_affine {
            x: parse_fp2_from_bytes_blst(&proof_b_g2_bytes[0..96]),
            y: parse_fp2_from_bytes_blst(&proof_b_g2_bytes[96..192]),
        };
        let mut p2_bytes_be = [0u8;192];
        unsafe {
            let blst_fp_ptr: *const blst::blst_p2_affine = &blst_proof_b;

            blst_p2_affine_serialize(
                p2_bytes_be.as_mut_ptr(),
                blst_fp_ptr
            );
        };
        let b = G2Affine::from_uncompressed(&p2_bytes_be).unwrap();
        let res_ml_blstrs = <Bls12>::multi_miller_loop(&[(&a, &b.into())]);
        // println!("proof.a {}",proof.a);
        // println!("a {}",a);
        //
        // println!("proof.b {}",proof.b);
        // println!("b {}",b);
        let res_pairing_blstrs = <Bls12>::pairing(&a, &b.into());
        println!("res_ml_blstrs {:?}", res_ml_blstrs.final_exponentiation());
        println!("pairing_output {}", pairing_output);



        // println!("res_ml_blstrs {:?}", res_ml_blstrs);
        // println!("miller_output {}", miller_output);



}
