use neptune::*;
use blstrs::Scalar as Fr;
use generic_array::typenum::{U2, U3, U4, U5};
use neptune::poseidon::PoseidonConstants;

pub fn poseidon_neptun(){
    let constants = PoseidonConstants::<Fr, U2>::new_with_strength(Strength::Standard);
    println!("round_constants {:?}", constants.round_constants.len());
    let mut h = Poseidon::<Fr, U2>::new(&constants);
    let input = Fr::from(1 as u64);
     h.input(input).unwrap();
     h.input(input).unwrap();
     let output =h.hash();
     println!("{:?}", output.to_bytes_le());

     let constants = PoseidonConstants::<Fr, U3>::new_with_strength(Strength::Standard);
     let mut h = Poseidon::<Fr, U3>::new(&constants);
     let input = Fr::from(1 as u64);
     for _ in 0..3 {
         h.input(input).unwrap();
     }
      let output =h.hash();
      println!("{:?}", output.to_bytes_le());

      let constants = PoseidonConstants::<Fr, U4>::new_with_strength(Strength::Standard);
      let mut h = Poseidon::<Fr, U4>::new(&constants);
      let input = Fr::from(1 as u64);
      for _ in 0..4 {
          h.input(input).unwrap();
      }
       let output =h.hash();
       println!("{:?}", output.to_bytes_le());

       let constants = PoseidonConstants::<Fr, U5>::new_with_strength(Strength::Standard);
       let mut h = Poseidon::<Fr, U5>::new(&constants);
       let input = Fr::from(1 as u64);
       for _ in 0..5 {
           h.input(input).unwrap();
       }
        let output =h.hash();
        println!("{:?}", output.to_bytes_le());
}
