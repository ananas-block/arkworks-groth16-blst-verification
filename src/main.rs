#![allow(unused)]

use blstrs::*;
use blst_verification_test::parsers::*;
use blst_verification_test::arkworks_circuit::*;
use blst::blst_miller_loop;
use blst::*;
use blst_verification_test::blstrs_test::*;


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
use std::ops::Neg;

use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use std::ops::MulAssign;
fn groth_16_test() {

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
        println!(" proof.a {:?}", proof.a);

        let proof_a_g1 = proof.a;//(prepared_inputs).into_affine();

        let mut proof_a_g1_bytes = vec![0u8;96];
        parse_proof_a_or_c_to_bytes(proof_a_g1, &mut proof_a_g1_bytes);
        println!("proof.a.into(): {:?}",proof_a_g1_bytes);

        let proof_b_g2 = proof.b;//params.vk.gamma_g2;

        let mut proof_b_g2_bytes = vec![0u8;192];
        parse_proof_b_to_bytes(proof_b_g2, &mut proof_b_g2_bytes);
        println!("proof.b.into(): {:?}", proof_b_g2_bytes);


        let proof_prep_g1 = (prepared_inputs).into_affine();
        let mut proof_prep_g1_bytes = vec![0u8;96];
        parse_proof_a_or_c_to_bytes(proof_prep_g1, &mut proof_prep_g1_bytes);

        let proof_gamma_g2 = params.vk.gamma_g2.neg();

        let mut proof_gamma_g2_bytes = vec![0u8;192];
        parse_proof_b_to_bytes(proof_gamma_g2, &mut proof_gamma_g2_bytes);

        let proof_c_g1 = proof.c;
        let mut proof_c_g1_bytes = vec![0u8;96];
        parse_proof_a_or_c_to_bytes(proof_c_g1, &mut proof_c_g1_bytes);

        let proof_delta_g2 = params.vk.delta_g2.neg();
        let mut proof_delta_g2_bytes = vec![0u8;192];
        parse_proof_b_to_bytes(proof_delta_g2, &mut proof_delta_g2_bytes);

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
        let res_origin = <ark_ec::models::bls12::Bls12::<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::final_exponentiation(&miller_output).unwrap();

        //let pairing_output = <ark_ec::models::bls12::Bls12::<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::pairing(proof.a, proof.b);
        //assert_eq!(pairing_output, res_origin, "pairing vs manual");
        //println!("miller_output {:?}", miller_output);
        let blst_proof_a = get_p1_affine(&proof_a_g1_bytes);
        let blst_proof_b = get_p2_affine(&proof_b_g2_bytes);

        let blst_proof_1_g1 = get_p1_affine(&proof_prep_g1_bytes);
        let blst_proof_1_g2 = get_p2_affine(&proof_gamma_g2_bytes);

        let blst_proof_2_g1 = get_p1_affine(&proof_c_g1_bytes);
        let blst_proof_2_g2 = get_p2_affine(&proof_delta_g2_bytes);
        // println!("blst_p2_affine.x {:?}", blst_proof_b.x);
        // println!("blst_p2_affine.y {:?}", blst_proof_b.y);
        /*
        let blst_proof_1_g1  = blst_p1_affine {
            x: read_fp_blst(&proof_prep_g1_bytes[0..48]),
            y: read_fp_blst(&proof_prep_g1_bytes[48..96]),
        };

        let blst_proof_1_g2 = blst_p2_affine {
            x: parse_fp2_from_bytes_blst(&proof_gamma_g2_bytes[0..96]),
            y: parse_fp2_from_bytes_blst(&proof_gamma_g2_bytes[96..192]),
        };

        let blst_proof_2_g1  = blst_p1_affine {
            x: read_fp_blst(&proof_c_g1_bytes[0..48]),
            y: read_fp_blst(&proof_c_g1_bytes[48..96]),
        };

        let blst_proof_2_g2 = blst_p2_affine {
            x: parse_fp2_from_bytes_blst(&proof_delta_g2_bytes[0..96]),
            y: parse_fp2_from_bytes_blst(&proof_delta_g2_bytes[96..192]),
        };
        */
        let mut dst = [0u8; 3];
        let mut prng = Pairing::new(true, &dst);
        //prng.init(false, &dst);

        prng.raw_aggregate(&blst_proof_b, &blst_proof_a);
        prng.raw_aggregate(&blst_proof_1_g2, &blst_proof_1_g1);
        prng.raw_aggregate(&blst_proof_2_g2, &blst_proof_2_g1);
        println!("pre ml(commit): {:?}", prng.as_fp12());
        let mut fqk_ark_bytes = vec![0u8;576];

        parse_f_to_bytes(miller_output, &mut fqk_ark_bytes);
        prng.commit();

        //assert_eq!( prng.as_fp12(),parse_fp12_from_bytes_blst(&fqk_ark_bytes),"fucking blst miller_loop");

        // println!("after ml(commit): {:?}", prng.as_fp12());
        /*let mut lines = vec![blst_fp6::default(); 68];

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

        unsafe {
            blst::blst_fp12_mul(&mut tmp0, &tmp0, &tmp1);
        }
        unsafe {
            blst::blst_fp12_mul(&mut tmp0, &tmp0, &tmp2);
        }*/

        let mut tmp0 = blst_fp12::default();
        unsafe { blst_miller_loop(&mut tmp0, &blst_proof_b, &blst_proof_a) };

        let mut tmp1 = blst_fp12::default();
        unsafe { blst_miller_loop(&mut tmp1, &blst_proof_1_g2, &blst_proof_1_g1) };
        let mut tmp2 = blst_fp12::default();
        unsafe { blst_miller_loop(&mut tmp2, &blst_proof_2_g2, &blst_proof_2_g1) };

        let mut result = blst_fp12::default();
        //tmp0.mul_assign(tmp0);
        tmp0.mul_assign(tmp1);
        tmp0.mul_assign(tmp2);



        //let res = prng.finalverify(None);
        println!("prng res: {:?}", prng.as_fp12());

        parse_f_to_bytes(pvk.alpha_g1_beta_g2, &mut fqk_ark_bytes);
        println!("pvk.alpha_g1_beta_g2: {:?}", pvk.alpha_g1_beta_g2);

        //println!("prng after final exp: {:?}", prng.as_fp12().final_exp());
        //println!("res: {}", res);
        // assert_eq!(res_origin, pvk.alpha_g1_beta_g2, "arkworks lib failed");

        //let fe_blst = parse_fp12_from_bytes_blst(&fqk_ark_bytes).final_exp();
        parse_f_to_bytes(res_origin, &mut fqk_ark_bytes);
        let other_res = prng.as_fp12().final_exp();
        //assert_eq!(prng.as_fp12(), parse_fp12_from_bytes_blst(&fqk_ark_bytes), "final exp blst failed");
        println!("res_origin {}", res_origin);
        assert_eq!(tmp0.final_exp(), parse_fp12_from_bytes_blst(&fqk_ark_bytes), "final exp blst failed");

        assert_eq!(prng.as_fp12().final_exp(), tmp0.final_exp(), "final exp blst failed commit");

        // assert_eq!(tmp0.final_exp(), parse_fp12_from_bytes_blst(&fqk_ark_bytes), "final exp blst failed");
        //assert_eq!(res_origin, pvk.alpha_g1_beta_g2, "blst lib failed");

        //assert!(res, "blst verification failed");

        // parse_f_to_bytes(miller_output, &mut fqk_ark_bytes);
        // println!("miller_output: {:?}", miller_output);
        // assert_eq!(prng.as_fp12(), parse_fp12_from_bytes_blst(&fqk_ark_bytes));

        /*
        let mut    fqk_ark_bytes = vec![0u8;576];
        parse_f_to_bytes(final_exponentiation_ark, &mut fqk_ark_bytes);

        let blst_fp12 = parse_fp12_from_bytes_blst(&fqk_ark_bytes);
        let res_origin = <ark_ec::models::bls12::Bls12::<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::final_exponentiation(&miller_output).unwrap();

        assert_eq!(res_origin, pvk.alpha_g1_beta_g2);
        println!("success custom");*/
    }
}

fn get_p1_affine(proof_a_g1_bytes: &[u8]) -> blst_p1_affine {
    let mut  blst_proof_a_man = blst_p1_affine {
        x: read_fp_blst(&proof_a_g1_bytes[0..48]),
        y: read_fp_blst(&proof_a_g1_bytes[48..96]),
    };
    let mut p1_a_bytes_be = [0u8;96];
    unsafe {
        let blst_fp_ptr: *const blst::blst_p1_affine = &blst_proof_a_man;

        blst_p1_affine_serialize(
            p1_a_bytes_be.as_mut_ptr(),
            blst_fp_ptr
        );
    };
    println!("p1_a_bytes_be {:?}", p1_a_bytes_be);
    let mut blst_proof_a = blst_p1_affine::default();
    unsafe {
       blst_p1_deserialize(&mut blst_proof_a, p1_a_bytes_be.as_ptr());
    }
    blst_proof_a
}
fn get_p2_affine(proof_b_g2_bytes: &[u8]) -> blst_p2_affine {
    let mut p2_b_bytes_be = [0u8;96];

    let blst_proof_b_man = blst_p2_affine {
        x: parse_fp2_from_bytes_blst(&proof_b_g2_bytes[0..96]),
        y: parse_fp2_from_bytes_blst(&proof_b_g2_bytes[96..192]),
    };
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
    blst_proof_b

}
use ark_ff::BigInteger;
fn le_vs_be_test(){
    // result if I reverse the order of bytes then the results are the same
    // parsing bigints not fp384 results in different numbers
    let mut rng = &mut test_rng();
    let fp = Fp384::<ark_bls12_381::FqParameters>::rand(&mut rng);
    println!("fp : {:?}", fp);

    let mut fp_bytes_le = Vec::with_capacity(48);
    <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
        &fp,
        &mut fp_bytes_le,
    ).unwrap();
    //fp_bytes_le = fp.0.to_bytes_le();
    let mut p1_a_bytes_be = vec![0u8;48];
    println!("bytes_le: {:?}", fp_bytes_le);

    for (i, elem) in fp_bytes_le.iter().rev().enumerate(){
        p1_a_bytes_be[i] = *elem;
    }


    println!("bytes_be : {:?}", p1_a_bytes_be.to_vec());
    println!("bytes_le: {:?}", fp_bytes_le);
    println!("read_fp_blst_be: {:?}", read_fp_blst_be(&p1_a_bytes_be[..]));
    println!("read_fp_blst_le: {:?}", read_fp_blst(&fp_bytes_le));

}

fn main() {
    //println!("g1 affine default: {:?}", );
    //le_vs_be_test();
    groth_16_test();
    //blstrs_test();
    // let mut dst = [0u8; 96 * 3 + 192 * 3];
    // let mut prng = Pairing::new(false, &dst);
    // println!("prng: {:?}", prng);
    // prng.init(false, &dst);
    // println!("prng: {:?}", prng);
    // prng.raw_aggregate();

    /*

    paring init

    blst_pairing_raw_aggregate()

    blst_pairing_commit(ctx)
    pairing commit

    blst_pairing_finalverify()

    let mut rng = &mut test_rng();
    let mut fqk_ark_bytes = vec![0u8;576];
    let fyk = <ark_ec::models::bls12::Bls12<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::Fqk::rand(&mut rng);
    parse_f_to_bytes(fyk, &mut fqk_ark_bytes);
    println!("{:?}", fyk);


    let final_exponentiation_ark = <ark_ec::models::bls12::Bls12::<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::final_exponentiation(&fyk).unwrap();
    parse_f_to_bytes(final_exponentiation_ark, &mut fqk_ark_bytes);

    let blst_fp12 = parse_fp12_from_bytes_blst(&fqk_ark_bytes);
    let mut final_exponentiation_blst = blst_fp12.clone();
    println!("{:?}", blst_fp12);

    // g1 , g2
    unsafe { blst_miller_loop(&mut tmp, &q.0, &p.0) };


    let mut blst_fp12_bytes = vec![0u8;576];
    unsafe { blst_final_exp(&mut final_exponentiation_blst, &blst_fp12) };

    println!("{:?}", final_exponentiation_ark);

    println!("{:?}", blst_fp12);
    */
    //assert_eq!(blst_fp12_bytes,fqk_ark_bytes);

    /*
    let mut fp384_ark_bytes = vec![];
    let fp384_ark = Fp384::<ark_bls12_381::FqParameters>::rand(&mut rng);
    println!("{:?}", fp384_ark);
    let mut fp384_ark_bytes_2 = vec![];

    <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
        &fp384_ark,
        &mut fp384_ark_bytes_2,
    )
    .unwrap();
    for (i, data) in fp384_ark.0.0.iter().enumerate() {
        //fp384_ark_bytes.push(u64::to_le_bytes(*data));
        u64::to_le_bytes(*data).map(|x| fp384_ark_bytes.push(x));
    }
    println!("{:?}", fp384_ark_bytes);


    let mut l = [0u64;6];
    for (i, data) in fp384_ark_bytes.chunks(8).enumerate() {
        l[i] = u64::from_le_bytes((*data).try_into().unwrap());
    }
    let mut blst_fp = blst_fp {
        l: l,
    };
    println!("{:?}", blst_fp);
    let blst_fp2 = blst_fp2 {
        fp: [blst_fp; 2],
    };
    //let blst_fp2 = parse_fp2_from_bytes_blst(&[fp384_ark_bytes, fp384_ark_bytes].concat());
    // unsafe { blst_fp_add(&mut blst_fp, &blst_fp, &blst_fp) };
    // println!("{:?}", blst_fp);
    // unsafe {
    //     let fp384_ark_bytes_ptr: *const u8 = &fp384_ark_bytes_2[0];
    //     let blst_fp_ptr: *mut blst::blst_fp = &mut blst_fp;
    //
    //     blst_fp_from_lendian(blst_fp_ptr, fp384_ark_bytes_ptr);
    //     println!("{:?}", *blst_fp_ptr);
    // }
    blst_fp = read_fp_blst(&fp384_ark_bytes_2);
    println!("{:?}", blst_fp);*/

    //let mut blst_fp: blst_fp = blst_fp::try_from(&fp384_ark_bytes.into()).unwrap();
    //blst_fp_from_lendian(blst_fp, fp384_ark.to_bytes());
    // let mut bytes: &mut[u8];
    // blst_lendian_from_fp(&mut bytes, blst_fp)

}
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
