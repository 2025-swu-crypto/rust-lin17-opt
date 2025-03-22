use std::{marker::PhantomData, time::Instant};
use paillier::Paillier;
use paillier::*;
use gmp::mpz::{Mpz, ProbabPrimeResult};
use gmp::rand::RandState;
use curv::BigInt;
use curv::arithmetic::{BasicOps, BitManipulation, Converter};

// use paillier::{Decrypt, EncryptWithChosenRandomness, KeyGeneration};
// use paillier::{DecryptionKey, EncryptionKey, Randomness, RawCiphertext, RawPlaintext};

#[cfg(not(test))] 
use log::{info, warn}; // Use log crate when building application
 
#[cfg(test)]
use std::{println as info, println as warn};



pub fn paillier_add() {
    let mut state: RandState = RandState::new();

    // generate a fresh keypair and extract encryption and decryption keys
    let (ek, dk) = Paillier::keypair_with_modulus_size(3072).keys();
    info!("ek.n-bit {:?}", ek.n.clone().bit_length());
    // samples random k-bit msg
    let k: u32 = 768;
    let k_pow = Mpz::from(2).pow(k);
    let m1 = RandState::urandom(&mut state, &Mpz::from(k_pow.clone()));
    let s1 = RandState::urandom(&mut state, &Mpz::ui_pow_ui(2,256 ));

    let m1_bi = BigInt::from_str_radix(&m1.to_str_radix(10), 10).unwrap();
    let s1_bi: BigInt = BigInt::from_str_radix(&s1.to_str_radix(10), 10).unwrap();

    let randomness = Randomness::sample(&ek);


    // encrypt four values
    let start_time = Instant::now();
    let c1 = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(m1_bi.clone()),
        &randomness,
    );
    // .0.into_owned();
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
	info!("enc c1 time: {:?}", elapsed_time);

    
    let start_time = Instant::now();
    let c2 = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(m1_bi.clone()),
        &randomness,
    );
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
	info!("enc c2 time: {:?}", elapsed_time);


    let start_time = Instant::now();
    let c3 = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(m1_bi.clone()),
        &randomness,
    );
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
	info!("enc c3 time: {:?}", elapsed_time);


    let s1 = RawPlaintext::from(s1_bi.clone());
  
    // add all of them together

    let start_time = Instant::now();
    let c = Paillier::add(&ek, c1, c2);
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
	info!("add c1+c2 time: {:?}", elapsed_time);

    let m = Paillier::decrypt(&dk, c);

    assert_eq!(m1_bi.clone() + m1_bi.clone(), m.into());



    let start_time = Instant::now();
    let c2 = Paillier::mul(&ek, c3, s1);
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
	info!("mul c3+s1 time: {:?}", elapsed_time);

    let start_time = Instant::now();
    let m2 = Paillier::decrypt(&dk, c2);
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
	info!("dec c3+s1 time: {:?}", elapsed_time);

    assert_eq!(m1_bi.clone() * s1_bi.clone(), m2.into());
    // let c = Paillier::add(&ek,
    //   &Paillier::add(&ek, &c1, &c2),
    //   &Paillier::add(&ek, &c3, &c4)
    // );
  
    // multiply the sum by 2
    // let d = Paillier::mul(&ek, &c, 2);
  
    // decrypt final result
    // let m: u64 = Paillier::decrypt(&dk, &d);
    // println!("decrypted total sum is {}", m);
  
  }