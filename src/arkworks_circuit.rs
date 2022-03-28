#![allow(unused)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    variant_size_differences,
    stable_features,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    private_in_public
)]

// For randomness (during paramgen and proof generation)
use ark_std::rand::Rng;

// For benchmarking
use std::time::{Duration, Instant};

// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-377 pairing-friendly elliptic curve.
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{Field, Fp384, BigInteger};
use ark_std::test_rng;
use ark_ff::bytes::{FromBytes, ToBytes};

// We'll use these interfaces to construct our circuit.
use ark_relations::{
    lc, ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use blst::*;

pub const MIMC_ROUNDS: usize = 322;

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3` for BLS12-377.
/// See http://eprint.iacr.org/2016/492 for more
/// information about this construction.
///
/// ```
/// function LongsightF322p3(xL ⦂ Fp, xR ⦂ Fp) {
///     for i from 0 up to 321 {
///         xL, xR := xR + (xL + Ci)^3, xL
///     }
///     return xL
/// }
/// ```
pub fn mimc<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    for i in 0..MIMC_ROUNDS {
        let mut tmp1 = xl;
        tmp1.add_assign(&constants[i]);
        let mut tmp2 = tmp1;
        tmp2.square_in_place();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
pub struct MiMCDemo<'a, F: Field> {
    pub xl: Option<F>,
    pub xr: Option<F>,
    pub constants: &'a [F],
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, F: Field> ConstraintSynthesizer<F> for MiMCDemo<'a, F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.
        let mut xl_value = self.xl;
        let mut xl =
            cs.new_witness_variable(|| xl_value.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocate the second component of the preimage.
        let mut xr_value = self.xr;
        let mut xr =
            cs.new_witness_variable(|| xr_value.ok_or(SynthesisError::AssignmentMissing))?;

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL
            let ns = ns!(cs, "round");
            let cs = ns.cs();

            // tmp = (xL + Ci)^2
            let tmp_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square_in_place();
                e
            });
            let tmp =
                cs.new_witness_variable(|| tmp_value.ok_or(SynthesisError::AssignmentMissing))?;

            cs.enforce_constraint(
                lc!() + xl + (self.constants[i], Variable::One),
                lc!() + xl + (self.constants[i], Variable::One),
                lc!() + tmp,
            )?;

            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let new_xl_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            });

            let new_xl = if i == (MIMC_ROUNDS - 1) {
                // This is the last round, xL is our image and so
                // we allocate a public input.
                cs.new_input_variable(|| new_xl_value.ok_or(SynthesisError::AssignmentMissing))?
            } else {
                cs.new_witness_variable(|| new_xl_value.ok_or(SynthesisError::AssignmentMissing))?
            };

            cs.enforce_constraint(
                lc!() + tmp,
                lc!() + xl + (self.constants[i], Variable::One),
                lc!() + new_xl - xr,
            )?;

            // xR = xL
            xr = xl;
            xr_value = xl_value;

            // xL = new_xL
            xl = new_xl;
            xl_value = new_xl_value;
        }

        Ok(())
    }
}

pub fn write_be(fp384: &Fp384<ark_bls12_381::FqParameters>, range: &mut Vec<u8>) {
    *range = fp384.0.to_bytes_be();

}

pub fn parse_f_to_bytes_be(
    f: <ark_ec::models::bls12::Bls12<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::Fqk,
    //range: &mut Vec<u8>,
) -> Vec<u8> {
    let range = vec![0u8; 576];
    let mut iter = 0;
    for i in 0..2_u8 {
        println!("range: {:?}", range);
        for j in 0..3_u8 {
            for z in 0..2_u8 {
                let tmp = iter;
                iter += 48;
                if i == 0 {
                    if j == 0 && z == 0 {
                        write_be(
                            &f.c0.c0.c0,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 1 && z == 0 {
                        write_be(
                            &f.c0.c1.c0,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 2 && z == 0 {
                        write_be(
                            &f.c0.c2.c0,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 0 && z == 1 {
                        write_be(
                            &f.c0.c0.c1,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 1 && z == 1 {
                        write_be(
                            &f.c0.c1.c1,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 2 && z == 1 {
                        write_be(
                            &f.c0.c2.c1,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    }
                } else if i == 1 {
                    if j == 0 && z == 0 {
                        write_be(
                            &f.c1.c0.c0,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 1 && z == 0 {
                        write_be(
                            &f.c1.c1.c0,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 2 && z == 0 {
                        write_be(
                            &f.c1.c2.c0,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 0 && z == 1 {
                        write_be(
                            &f.c1.c0.c1,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 1 && z == 1 {
                        write_be(
                            &f.c1.c1.c1,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    } else if j == 2 && z == 1 {
                        write_be(
                            &f.c1.c2.c1,
                             &mut range[tmp..iter].to_vec(),
                        )
                        ;
                    }
                }
            }
        }
    }
    range
}


pub fn parse_f_to_bytes(
    f: <ark_ec::models::bls12::Bls12<ark_bls12_381::Parameters> as ark_ec::PairingEngine>::Fqk,
    range: &mut Vec<u8>,
) {
    let mut iter = 0;
    for i in 0..2_u8 {
        for j in 0..3_u8 {
            for z in 0..2_u8 {
                let tmp = iter;
                iter += 48;
                if i == 0 {
                    if j == 0 && z == 0 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c0.c0.c0,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 1 && z == 0 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c0.c1.c0,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 2 && z == 0 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c0.c2.c0,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 0 && z == 1 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c0.c0.c1,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 1 && z == 1 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c0.c1.c1,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 2 && z == 1 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c0.c2.c1,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    }
                } else if i == 1 {
                    if j == 0 && z == 0 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c1.c0.c0,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 1 && z == 0 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c1.c1.c0,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 2 && z == 0 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c1.c2.c0,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 0 && z == 1 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c1.c0.c1,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 1 && z == 1 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c1.c1.c1,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    } else if j == 2 && z == 1 {
                        <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(
                            &f.c1.c2.c1,
                            &mut range[tmp..iter],
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
}

pub fn read_fp_blst_be(fp384_ark_bytes_2: &[u8]) -> blst::blst_fp {
    let mut blst_fp: &mut blst::blst_fp = &mut blst_fp::default();
    unsafe {
        let fp384_ark_bytes_ptr: *const u8 = &fp384_ark_bytes_2[0];
        let blst_fp_ptr: *mut blst::blst_fp = blst_fp;

        blst_fp_from_bendian(blst_fp_ptr, fp384_ark_bytes_ptr);
        *blst_fp = *blst_fp_ptr;
    }
    *blst_fp
}
pub fn parse_fp2_from_bytes_blst_be(
    bytes: &[u8],
) -> blst::blst_fp2 {
    blst_fp2 {
        fp: bytes.chunks(48).map(|fp_bytes| read_fp_blst_be(&fp_bytes)).collect::<Vec<blst_fp>>().try_into().unwrap(),
    }
}

pub fn read_fp_blst(fp_bytes_le: &[u8]) -> blst::blst_fp {
    let mut fp_bytes_be = vec![0u8;48];
    //println!("bytes_le: {:?}", fp_bytes_le);

    for (i, elem) in fp_bytes_le.iter().rev().enumerate(){
        fp_bytes_be[i] = *elem;
    }

    let mut blst_fp: &mut blst::blst_fp = &mut blst_fp::default();
    unsafe {
        let fp384_ark_bytes_ptr: *const u8 = &fp_bytes_be[0];
        let blst_fp_ptr: *mut blst::blst_fp = blst_fp;

        blst_fp_from_bendian(blst_fp_ptr, fp384_ark_bytes_ptr);
        *blst_fp = *blst_fp_ptr;
    }
    *blst_fp
}

pub fn parse_fp2_from_bytes_blst(
    bytes: &[u8],
) -> blst::blst_fp2 {
    blst_fp2 {
        fp: bytes.chunks(48).map(|fp_bytes| read_fp_blst(&fp_bytes)).collect::<Vec<blst_fp>>().try_into().unwrap(),
    }
}
pub fn parse_fp6_from_bytes_blst(
    bytes: &[u8]
) -> blst::blst_fp6 {
    blst_fp6 {
        fp2: bytes.chunks(96).map(|fp2_bytes| parse_fp2_from_bytes_blst(&fp2_bytes)).collect::<Vec<blst_fp2>>().try_into().unwrap(),
    }
}
pub fn parse_fp12_from_bytes_blst(
    bytes: &[u8]
) -> blst::blst_fp12 {
    blst_fp12 {
        fp6: bytes.chunks(288).map(|fp6_bytes| parse_fp6_from_bytes_blst(&fp6_bytes)).collect::<Vec<blst_fp6>>().try_into().unwrap(),
    }
}

/*
#[test]
fn test_mimc_gm_17() {
    // We're going to use the Groth-Maller17 proving system.
    use ark_groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

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

    println!("Creating proofs...");

    // Let's benchmark stuff!
    const SAMPLES: u32 = 50;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    // Just a place to put the proof data, so we can
    // benchmark deserialization.
    // let mut proof_vec = vec![];

    for _ in 0..SAMPLES {
        // Generate a random preimage and compute the image
        let xl = rng.gen();
        let xr = rng.gen();
        let image = mimc(xl, xr, &constants);

        // proof_vec.truncate(0);

        let start = Instant::now();
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

            // proof.write(&mut proof_vec).unwrap();
        }

        total_proving += start.elapsed();

        let start = Instant::now();
        // let proof = Proof::read(&proof_vec[..]).unwrap();
        // Check the proof

        total_verifying += start.elapsed();
    }
    let proving_avg = total_proving / SAMPLES;
    let proving_avg =
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);

    println!("Average proving time: {:?} seconds", proving_avg);
    println!("Average verifying time: {:?} seconds", verifying_avg);
}
*/
