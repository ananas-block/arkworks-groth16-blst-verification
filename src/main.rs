#![allow(unused)]
use blst_verification_test::blstrs_poc::*;
use blst_verification_test::blst_poc::groth_16_verification_with_blst;

fn main() {
    //println!("g1 affine default: {:?}", );
    //le_vs_be_test();
    groth_16_verification_with_blst();
    println!("test successful");
    //blstrs_test();
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
