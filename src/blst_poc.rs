#![allow(unused)]
use blstrs::*;
use crate::arkworks_circuit::*;
use blst::*;
use crate::blstrs_poc::*;
use ark_ff::BigInteger;
use crate::parsers::*;
use crate::ITERATIONS;
// For randomness (during paramgen and proof generation)
use ark_std::rand::Rng;

// For benchmarking
use std::time::{Duration, Instant};

// Bring in some tools for using pairing-friendly curves
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff;
use ark_ff::Field;
use ark_std::test_rng;
use ark_groth16::prepare_inputs;
use ark_ec::ProjectiveCurve;

use ark_ff::{Fp384, Fp256};
use ark_bn254;
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
use std::ops::Neg;

use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use std::ops::MulAssign;
use byte_slice_cast::AsByteSlice;

pub fn groth_16_verification_with_blst() {

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

    {
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
        let miller_output =
            <ark_ec::models::bls12::Bls12::<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::miller_loop(
                [
                    (proof.a.into(), proof.b.into()),
                    (
                        (prepared_inputs).into_affine().into(),
                        pvk.gamma_g2_neg_pc.clone(),
                    ),
                    (proof.c.into(), pvk.delta_g2_neg_pc.clone()),
                ]
                .iter(),
        );
        let arkworks_final_exp_res = <ark_ec::models::bls12::Bls12::<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::final_exponentiation(&miller_output).unwrap();
        let mut fqk_ark_bytes = vec![0u8; 576];
        parse_f_to_bytes(arkworks_final_exp_res, &mut fqk_ark_bytes);
        let ark_works_ref_final_exp_as_blst = parse_fp12_from_bytes_blst(&fqk_ark_bytes);
        let mut fqk_alpha_g1_beta_g2_ark_bytes = vec![0u8;576];
        parse_f_to_bytes(pvk.alpha_g1_beta_g2, &mut fqk_alpha_g1_beta_g2_ark_bytes);
        let fqk_alpha_g1_beta_g2_ark_blst = parse_fp12_from_bytes_blst(&fqk_alpha_g1_beta_g2_ark_bytes);
        // println!("pvk.alpha_g1_beta_g2: {:?}", pvk.alpha_g1_beta_g2);
        // println!("fqk_alpha_g1_beta_g2_ark_blst: {:?}", fqk_alpha_g1_beta_g2_ark_blst);
        // panic!();


        // creates proof data bytes offchain



        let proof_a_g1 = proof.a;
        let mut proof_a_g1_bytes = vec![0u8;96];
        parse_proof_a_or_c_to_bytes(proof_a_g1, &mut proof_a_g1_bytes);

        let proof_b_g2 = proof.b;//params.vk.gamma_g2;
        let mut proof_b_g2_bytes = vec![0u8;192];
        parse_proof_b_to_bytes(proof_b_g2, &mut proof_b_g2_bytes);

        // scalars are public inputs
        // create scalar(s) of public input(s) offchain
        let scalar_bytes = create_scalar_bytes_offchain(&image);
        // create pvk affines these values should be hardcoded onchain
        let mut p1_pvk_0 = create_public_inputs_pvk(&params.vk.gamma_abc_g1[0]);
        let mut p1_pvk_1 = create_public_inputs_pvk(&params.vk.gamma_abc_g1[1]);

        // verifyingkey should be hardcoded onchain
        let proof_gamma_g2 = params.vk.gamma_g2.neg();
        let mut proof_gamma_g2_bytes = vec![0u8;192];
        parse_proof_b_to_bytes(proof_gamma_g2, &mut proof_gamma_g2_bytes);

        let proof_c_g1 = proof.c;
        let mut proof_c_g1_bytes = vec![0u8;96];
        parse_proof_a_or_c_to_bytes(proof_c_g1, &mut proof_c_g1_bytes);

        // verifyingkey should be hardcoded onchain
        let proof_delta_g2 = params.vk.delta_g2.neg();
        let mut proof_delta_g2_bytes = vec![0u8;192];
        parse_proof_b_to_bytes(proof_delta_g2, &mut proof_delta_g2_bytes);


        // proof verification onchain

        let number_of_public_inputs = 1usize;
        // prepare inputs computation onchain
        for i in 0..number_of_public_inputs {

            // g1_affine_1.mul_assign(&scalar);
            // mul_assign
            let mut mul_assign = blst_p1::default();
            // Scalar is 255 bits wide.
            const NBITS: usize = 255;
            unsafe { blst_p1_mult(&mut mul_assign, &p1_pvk_1, scalar_bytes.as_ptr(), NBITS) };

            // let mut mul_assign_affine = blst_p1_affine::default();
            // unsafe { blst_p1_to_affine(&mut mul_assign_affine, &mul_assign) };

            //g_ic.add_assign(&g1_affine_1);
            unsafe { blst_p1_add(&mut p1_pvk_0, &p1_pvk_0, &mul_assign) };
        }

        let mut prepare_inputs_result_affine = blst_p1_affine::default();
        unsafe { blst_p1_to_affine(&mut prepare_inputs_result_affine, &p1_pvk_0) };

        //get proof and verifyingkey data from bytes
        let blst_proof_a = get_p1_affine(&proof_a_g1_bytes);
        let blst_proof_b = get_p2_affine(&proof_b_g2_bytes);

        let blst_proof_1_g1 = prepare_inputs_result_affine;
        let blst_proof_1_g2 = get_p2_affine(&proof_gamma_g2_bytes);

        let blst_proof_2_g1 = get_p1_affine(&proof_c_g1_bytes);
        let blst_proof_2_g2 = get_p2_affine(&proof_delta_g2_bytes);
        /*
        let ml_duration = Instant::now();
        for i in 0..ITERATIONS {
            // miller loop
            let mut tmp0 = blst_fp12::default();
            unsafe { blst_miller_loop(&mut tmp0, &blst_proof_b, &blst_proof_a) };
            let mut tmp1 = blst_fp12::default();
            unsafe { blst_miller_loop(&mut tmp1, &blst_proof_1_g2, &blst_proof_1_g1) };
            let mut tmp2 = blst_fp12::default();
            unsafe { blst_miller_loop(&mut tmp2, &blst_proof_2_g2, &blst_proof_2_g1) };
            tmp0.mul_assign(tmp1);
            tmp0.mul_assign(tmp2);

            // final exponentiation
            let mut result = blst_fp12::default();
            result = tmp0.final_exp();
            //assert_eq!(result, ark_works_ref_final_exp_as_blst, "blst verification failed");
        }
        println!("ml duration {}", ml_duration.elapsed().as_micros());

        let ml_lines_duration = Instant::now();
        for i in 0..ITERATIONS {
            // alternative miller loop with lines
            let mut lines = vec![blst_fp6::default(); 68];
            let mut tmp0 = blst_fp12::default();
            // lines are the coeffs doesn t change anything though same result
            unsafe { blst_precompute_lines(lines.as_mut_ptr(), &blst_proof_b) }

            unsafe { blst_miller_loop_lines(&mut tmp0, &lines[0], &blst_proof_a) };

            let mut tmp1 = blst_fp12::default();
            unsafe { blst_precompute_lines(lines.as_mut_ptr(), &blst_proof_1_g2) }

            unsafe { blst_miller_loop_lines(&mut tmp1, &lines[0], &blst_proof_1_g1) };
            let mut tmp2 = blst_fp12::default();
            unsafe { blst_precompute_lines(lines.as_mut_ptr(), &blst_proof_2_g2) }

            unsafe { blst_miller_loop_lines(&mut tmp2, &lines[0], &blst_proof_2_g1) };

            unsafe { blst::blst_fp12_mul(&mut tmp0, &tmp0, &tmp1) };
            unsafe { blst::blst_fp12_mul(&mut tmp0, &tmp0, &tmp2) };
            tmp0 = tmp0.final_exp();
            //assert_eq!(tmp0, ark_works_ref_final_exp_as_blst, "blst verification with lines failed");
        }
        println!("ml lines duration {}", ml_lines_duration.elapsed().as_micros());
        */
        //alternative with pairing class (fastest)
        let pairing_class_duration = Instant::now();
        for i in 0..ITERATIONS {
            let mut dst = [0u8; 3];
            let mut paring_blst = Pairing::new(true, &dst);
            paring_blst.raw_aggregate(&blst_proof_b, &blst_proof_a);
            paring_blst.raw_aggregate(&blst_proof_1_g2, &blst_proof_1_g1);
            paring_blst.raw_aggregate(&blst_proof_2_g2, &blst_proof_2_g1);
            paring_blst.commit();
            // final verify does not work
            // let res_pairing_blst = paring_blst.finalverify(Some(&ark_works_ref_final_exp_as_blst));
            // println!("res_pairing_blst {:?}",res_pairing_blst);
            // assert!(res_pairing_blst, "pairing_blst final verify failed");
            assert_eq!(paring_blst.as_fp12().final_exp(), ark_works_ref_final_exp_as_blst, "pairing_blst failed");
        }
        println!("duration pairing class {} over {} iterations", pairing_class_duration.elapsed().as_micros(), ITERATIONS);
        /*
        // finalverify check fails
        let res_pairing_blst = paring_blst.finalverify(Some(&fqk_alpha_g1_beta_g2_ark_blst));
        println!("{:?}",res_pairing_blst);
        assert!(res_pairing_blst, "pairing_blst failed");
        */
        println!("groth 16 verification with blst success");

    }
}



fn create_public_inputs_pvk(pvk_gamma_abc_g1_x: &ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bls12_381::g1::Parameters>) -> blst_p1 {
    let mut pvk_gamma_abc_g1_x_bytes = vec![0u8; 96];
    parse_proof_a_or_c_to_bytes(*pvk_gamma_abc_g1_x,&mut pvk_gamma_abc_g1_x_bytes);

    let affine_pvk_x = blst_p1_affine {
        x: read_fp_blst(&pvk_gamma_abc_g1_x_bytes[0..48]),
        y: read_fp_blst(&pvk_gamma_abc_g1_x_bytes[48..96])
    };
    let mut p1_pvk_x = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut p1_pvk_x, &affine_pvk_x) };

    p1_pvk_x
}

fn create_scalar_bytes_offchain(public_input: &Fr) -> [u8; 32]{

    let mut input_bytes = vec![];
    <Fr as ToBytes>::write(
        &public_input,
        &mut input_bytes,
    )
    .unwrap();

    let bytes_u64 = u64s_from_bytes(&input_bytes.clone().try_into().unwrap());

    let mut input_bytes_blst = blst_fr::default();

    unsafe { blst_fr_from_uint64(&mut input_bytes_blst, &bytes_u64[0]) };
    <blstrs::Scalar as From<blst_fr>>::from(input_bytes_blst).to_bytes_le()
}


/*
fn test_serialize_deserialize(){

    unsafe {
        let blst_fp_ptr: *const blst::blst_p2_affine = &blst_proof_b_man;

        blst_p2_affine_serialize(
            p2_b_bytes_be.as_mut_ptr(),
            blst_fp_ptr
        );
    };
    let mut blst_proof_b = blst_p2_affine::default();
    unsafe {
       blst_p2_deserialize(&mut blst_proof_b, p2_b_bytes_be.as_ptr());
   }
}*/
/*
fn try_compression() {
    let mut  blst_proof_a  = blst_p1_affine::default();
    blst_proof_a.x =  read_fp_blst(&proof_a_g1_bytes[0..48]);
    blst_proof_a.y =  read_fp_blst(&proof_a_g1_bytes[48..96]);
    assert_eq!(blst_proof_a, blst_p1_affine {
        x: read_fp_blst(&proof_a_g1_bytes[0..48]),
        y: read_fp_blst(&proof_a_g1_bytes[48..96]),
    });
    //println!("blst_proof_a {:?}", blst_proof_a);
    let proof_a_g1_bytes_first = &mut proof_a_g1_bytes[..48];
    let mut bytes = &mut [0u8;48];
    let mut blst_p1 = &mut blst_p1_affine::default();
    unsafe {
        let fp384_ark_bytes_ptr: *mut u8 = &mut proof_a_g1_bytes[0];
        let blst_fp_ptr: *const blst_p1_affine = blst_p1;

        blst_p1_affine_compress(fp384_ark_bytes_ptr, blst_fp_ptr);
        //blst_p1_uncompress(fp384_ark_bytes_ptr, blst_fp_ptr);

        // *bytes = *fp384_ark_bytes_ptr;
        // println!("{:?}", *bytes);

    }
    let mut out = [0u8; 48];

    unsafe {
       blst_p1_affine_compress(out.as_mut_ptr(), &blst_proof_a);
    }
    println!("blst_p1_affine_compress {:?} ", out);
    let mut raw = blst_p1_affine::default();
    let success =
        unsafe { blst_p1_uncompress(&mut raw, out.as_ptr())};
    println!("blst_p1_affine_compress {:?} ", raw);

}

fn try_map_to_g2() {
    let mut out = blst_p2::default();
    unsafe {
        blst_map_to_g2(&mut out, &params.vk.gamma_g2.y, &params.vk.gamma_g2.x);
    };
    println!("map to g2: {:?}", out);
    println!("ref g2 {:?}", pvk.gamma_g2_neg_pc);
}*/
