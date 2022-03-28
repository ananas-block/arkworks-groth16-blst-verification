use ark_bls12_381;
use ark_ec;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::fields::models::quadratic_extension::QuadExtField;
use ark_ff::Fp384;
use ark_ff::One;
use ark_ff::BigInteger;
use blst::*;
use crate::arkworks_circuit::*;
pub fn parse_proof_b_from_bytes(
    range: &Vec<u8>,
) -> ark_ec::models::bls12::g2::G2Affine<ark_bls12_381::Parameters> {
    ark_ec::models::bls12::g2::G2Affine::<ark_bls12_381::Parameters>::new(
        parse_quad_from_bytes(&range[..96].to_vec()),
        parse_quad_from_bytes(&range[96..].to_vec()),
        false,
    )
}

pub fn parse_proof_b_to_bytes(
    proof: ark_ec::models::bls12::g2::G2Affine<ark_bls12_381::Parameters>,
    range: &mut Vec<u8>,
) {
    let mut tmp0 = vec![0u8; 96];
    let mut tmp1 = vec![0u8; 96];
    parse_quad_to_bytes(proof.x, &mut tmp0);
    parse_quad_to_bytes(proof.y, &mut tmp1);
    *range = [tmp0, tmp1].concat();
}

pub fn parse_proof_b_to_bytes_be(
    proof: ark_ec::models::bls12::g2::G2Affine<ark_bls12_381::Parameters>,

) -> Vec<u8>{
    [parse_quad_to_bytes_be(proof.x), parse_quad_to_bytes_be(proof.y)].concat()
}

pub fn parse_quad_to_bytes_be(
    q: ark_ff::QuadExtField<ark_ff::Fp2ParamsWrapper<ark_bls12_381::Fq2Parameters>>,

) ->  Vec<u8> {
    let bytes_x = q.c0.0.to_bytes_be();
    let bytes_y = q.c1.0.to_bytes_be();
    [bytes_x, bytes_y].concat()
}


pub fn parse_quad_to_bytes(
    q: ark_ff::QuadExtField<ark_ff::Fp2ParamsWrapper<ark_bls12_381::Fq2Parameters>>,
    range: &mut Vec<u8>,
) {
    let mut iter = 0;

    for z in 0..2_u8 {
        let tmp = iter;
        iter += 48;
        if z == 0 {
            <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(&q.c0, &mut range[tmp..iter])
                .unwrap();
        } else if z == 1 {
            <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(&q.c1, &mut range[tmp..iter])
                .unwrap();
        }
    }
}

pub fn parse_quad_from_bytes(
    range: &Vec<u8>,
) -> ark_ff::QuadExtField<ark_ff::Fp2ParamsWrapper<ark_bls12_381::Fq2Parameters>> {
    let start = 0;
    let end = 96;
    let iter = start + 48;

    QuadExtField::<ark_ff::Fp2ParamsWrapper<ark_bls12_381::Fq2Parameters>>::new(
        <Fp384<ark_bls12_381::FqParameters> as FromBytes>::read(&range[start..iter]).unwrap(),
        <Fp384<ark_bls12_381::FqParameters> as FromBytes>::read(&range[iter..end]).unwrap(),
    )
}

pub fn parse_proof_a_or_c_from_bytes_be (
    account: &Vec<u8>,
) -> ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bls12_381::g1::Parameters> {
    ark_ec::short_weierstrass_jacobian::GroupAffine::<ark_bls12_381::g1::Parameters>::new(
        <Fp384<ark_bls12_381::FqParameters> as FromBytes>::read(&account[0..48]).unwrap(),
        <Fp384<ark_bls12_381::FqParameters> as FromBytes>::read(&account[48..96]).unwrap(),
        false,
    )
}

pub fn parse_proof_a_or_c_from_bytes(
    account: &Vec<u8>,
) -> ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bls12_381::g1::Parameters> {
    ark_ec::short_weierstrass_jacobian::GroupAffine::<ark_bls12_381::g1::Parameters>::new(
        <Fp384<ark_bls12_381::FqParameters> as FromBytes>::read(&account[0..48]).unwrap(),
        <Fp384<ark_bls12_381::FqParameters> as FromBytes>::read(&account[48..96]).unwrap(),
        false,
    )
}

pub fn parse_proof_a_or_c_to_bytes_be (
    x: ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bls12_381::g1::Parameters>,
) -> Vec<u8> {
    let mut bytes_x = x.x.0.to_bytes_be();
    let mut bytes_y = x.y.0.to_bytes_be();
    [bytes_x, bytes_y].concat()

    // <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(&x.x, &mut account[0..48]).unwrap();
    // <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(&x.y, &mut account[48..96]).unwrap();
}

pub fn parse_proof_a_or_c_to_bytes(
    x: ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bls12_381::g1::Parameters>,
    account: &mut Vec<u8>,
) {
    println!("x: {:?}", x);
    <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(&x.x, &mut account[0..48]).unwrap();
    <Fp384<ark_bls12_381::FqParameters> as ToBytes>::write(&x.y, &mut account[48..96]).unwrap();
}

pub fn u64s_from_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    println!("u64s_from_bytes: {:?}", bytes);
    [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ]
}

pub fn get_p1(proof_a_g1_bytes: &[u8]) -> blst_p1 {
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
    //println!("p1_a_bytes_be {:?}", p1_a_bytes_be);
    let mut blst_proof_a = blst_p1_affine::default();
    let mut out = blst_p1::default();

    unsafe {
       blst_p1_deserialize(&mut blst_proof_a, p1_a_bytes_be.as_ptr());

        unsafe { blst_p1_from_affine(&mut out, &blst_proof_a) };
    }
    out
}
