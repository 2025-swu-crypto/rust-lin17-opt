use std::borrow::Borrow;
use std::cmp::{Ordering};
use std::collections::HashMap;
use std::ops::Neg;
use std::io::Write;
use std::{marker::PhantomData, time::Instant};
use std::fs::{self, OpenOptions};
use std::fs::File;

use curv::arithmetic::Converter;
pub use curv::arithmetic::BigInt;


use gmp::mpz::{Mpz, ProbabPrimeResult};
use gmp::rand::RandState;


#[cfg(not(test))] 
use log::{info, warn}; // Use log crate when building application
 
#[cfg(test)]
use std::{println as info, println as warn};


// Public encryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionKey {
    pub N: BigInt,  // the modulus
    pub y: BigInt, // jacobi symbol 
    pub p: BigInt, 
}

/// Private decryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionKey {
    pub p: BigInt, // first prime
    pub q: BigInt, // second prime
}



// pub fn jl_generate_keypair_and_encrypted_share(
//     keygen: &EcKeyPair,
// ) -> (Mpz, Mpz, Mpz) {
//     let p_str: Vec<String> = fs::read_to_string("primes")
//         .unwrap()  // panic on possible file-reading    errors
//         .lines()  // split the string into an iterator of string slices
//         .map(String::from)  // make each slice into a string
//         .collect();  // gather them together into a vector;

//     let mut N: Mpz = Mpz::new();
//     let mut y: Mpz = Mpz::new();
//     let mut p: Mpz = Mpz::new();  

//     let mut state: RandState = RandState::new();

//     // 실제 사이즈로 수정한 상태 
//     let msgsize: u32 = 768;
//     // let msgsize_mpz = Mpz::from(2).pow(msgsize);
//     let keysize: u32 = 3200;


//     // running keygen, stored in N, y, p
//     if p_str.len() == 0 {
//         info!("start keygen");
//         // let start_time = Instant::now();
//         joye_libert_keygen(&mut N, &mut y, &mut p, msgsize, keysize);
//         info!("N: {:?}", N);
//         info!("N-bit: {:?}", N.bit_length());
//         info!("y: {:?}", y);
//         info!("p: {:?}", p);
    
//         // let end_time = Instant::now();
//         // let elapsed_time = end_time.duration_since(start_time);
//         // f.write_all(format!("keygen time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
//         // f2.write_all(N.to_str_radix(10).as_bytes()).expect("write failed");
//         // f2.write_all("\n".as_bytes()).expect("write failed");
//         // f2.write_all(y.to_str_radix(10).as_bytes()).expect("write failed");
//         // f2.write_all("\n".as_bytes()).expect("write failed");
//         // f2.write_all(p.to_str_radix(10).as_bytes()).expect("write failed");
//         // f2.write_all("\n".as_bytes()).expect("write failed");
//     } else {
//         N = Mpz::from_str_radix(&p_str[0], 10).unwrap();
//         y = Mpz::from_str_radix(&p_str[1], 10).unwrap();
//         p = Mpz::from_str_radix(&p_str[2], 10).unwrap();
//     }
//     // finish keygen

//     // start enc
//     // should get msg from lin17 -> parameter 
//     // +) mod msgsize as above
//     let mut encrypted_share = Mpz::new();
//     joye_libert_encrypt(&mut encrypted_share, &mut state, &keygen.secret_share, &y, &N, msgsize);


//     (y, N, encrypted_share)
// } 


pub fn joye_libert_keygen(
    mut N: &mut Mpz,
    mut y: &mut Mpz,
    mut p: &mut Mpz,
    mut q: &mut Mpz,
    msgsize: u32,
    keysize: u32,
) {
    let mut state: RandState = RandState::new();

    // let bigint_test = BigInt::from(2).to_str_radix(10);
    // let mpz_test = Mpz::from_str_radix(&bigint_test, 10).unwrap()-;

    // let mut q: Mpz = Mpz::new();
    let mut p_test: Mpz = Mpz::new();
    let mut q_test: Mpz = Mpz::new();


    let mut pseudo_safeness_divisor = Mpz::from(2);
    let mut pseudo_test_p = Mpz::new();
    let mut pseudo_test_q = Mpz::new();

    pseudo_safeness_divisor = Mpz::from(2).pow(msgsize);
    p_test = RandState::urandom_2exp(&mut state, (keysize/2) as u64);

    let mut modulus = Mpz::new();
    modulus = p_test.modulus(&pseudo_safeness_divisor);

    p_test = p_test - modulus;
    p_test = p_test + 1;

    let mut one = Mpz::one();


    let mut t = Mpz::new();
    let mut tmp = Mpz::new();

    // origin code에서 while 문 내부
    loop {
        // info!("p_test: {:?}", p_test);
        if p_test.probab_prime(30) != ProbabPrimeResult::NotPrime {
            // info!("p_test.probab_prime accepted");

            tmp = p_test.clone() - 1;
            pseudo_test_p = tmp / pseudo_safeness_divisor.clone();
            if pseudo_test_p.probab_prime(30) != ProbabPrimeResult::NotPrime {
                // info!("pseudo_test_p.probab_prime accepted") 
                *p = p_test.clone();
                break;
            }
        }    
        p_test += pseudo_safeness_divisor.clone();
    }
    info!("P loop finished");
    info!("p: {:?}", p);
    
    // 여기까지 

    q_test = RandState::urandom_2exp(&mut state, (keysize/2) as u64);
    q_test = q_test.nextprime();

    // origin code에서 while 문 내부
    loop {
        if q_test.probab_prime(30) != ProbabPrimeResult::NotPrime {
            // info!("q_test.probab_prime accepted");
            tmp = q_test.clone() % 4;
            if tmp == Mpz::from(3) {
                // info!("q_test % 4 == 3");
                *q = q_test.clone();
                break;
            }
        }
        q_test = q_test.nextprime();
    }
    info!("q loop finished");

    // 여기까지 

    *N = p.clone() * q.clone();

    *y = Mpz::from(3);

    // println!("jacobi test {:?}", Mpz::jacobi(&y, &N));


    while Mpz::jacobi(&y, &p) != -1 || Mpz::jacobi(&y, &q) != -1 {
        *y = RandState::urandom(&mut state, N);
    }
    info!("y: {:?}", y);

    return 
}


pub fn joye_libert_encrypt(
    mut c: &mut Mpz,
    state: &mut RandState,
    m: &Mpz,
    y: &Mpz,
    N: &Mpz,
    msgsize: u32,
) {
    let mut x = Mpz::from(0);
	// Pick a random x in Z_N^*
    while x.cmp(&Mpz::zero()) == Ordering::Equal {
        x = RandState::urandom(state, &N);
    }
    info!("x: {:?}", x);



	// Compute 2^msgsize
    let mut k_exp = Mpz::new();
    k_exp = Mpz::ui_pow_ui(2, msgsize);
    info!("k_exp: {:?}", k_exp);

    let mut tmp1 = Mpz::new();
    let mut tmp2 = Mpz::new();

    tmp1 = y.powm(&m, &N);
    tmp2 = x.powm(&k_exp, &N);
    info!("tmp1: {:?}", tmp1);
    info!("tmp2: {:?}", tmp2);


    info!("c: {:?}", *c);
    *c = tmp1.borrow() * tmp2.borrow();
    info!("c: {:?}", *c);
    *c = c.borrow() % N;
    info!("c: {:?}", *c);


    return
}

pub fn joye_libert_decrypt_bbb(
    mut m: &mut Mpz,
    c: &Mpz,
    p: &Mpz,
    y: &Mpz,
    msgsize: u32,
    n: u32,
    s: u32,
    TB: HashMap<Mpz, u32>,
    TD: &Vec<Mpz>,
) {
    // let start_time = Instant::now();
    let k = msgsize;
    let r = n * s - k;

    let mut B = 1;
    // let mut D = Mpz::new();
    let mut C = Mpz::new();

    *m = Mpz::zero();

    let mut exp_msgsize = Mpz::new();
    // let mut exp_y = Mpz::new();
    // let mut neg_exp_y = Mpz::new();
    let mut p_1 = Mpz::new();

    info!("c: {:?}", *c);
    let mut p_1 = p.clone() - 1;
    // p_1 -= 1;
    // info!("p: {:?}", p);
    // info!("p_1 = p - 1: {:?}", p_1);

    // exp_msgsize = Mpz::ui_pow_ui(2, k);
    info!("exp_msgsize: {:?}", exp_msgsize);
    let mut exp_y = p_1.clone() / Mpz::ui_pow_ui(2, k);
    // neg_exp_y = Mpz::neg(exp_y.clone());
    info!("exp_y: {:?}", exp_y);
    // info!("neg_exp_y: {:?}", neg_exp_y);
    
    C = c.powm(&exp_y, &p);


    let mut z = Mpz::new();
    for i in 0..(n-1) {
        let exp_c = Mpz::ui_pow_ui(2, k - (i + 1) * s);
        z = C.powm(&exp_c, &p);
        // info!("is z in B? {}", TB.contains_key(&z));
        // info!("z at i={}: {}", i, &z);
        // info!("B at i={}: {}", i, TB[&(z.clone())]);
        B = TB[&z];
        
        
        // TD
        // info!("B at i={}: {}", i, B);
        let new_idx = (i as usize) * 2_usize.pow(s) + B as usize;
        C *= TD[new_idx].borrow();
        C %= p; 


        let mut exp_2_is = Mpz::new();
        exp_2_is.setbit((i*s) as usize);


        *m += Mpz::from(B) * exp_2_is;
        // *m += Mpz::from((B as u32) << i*s); // B 자료형이 문제임 shift 관련 함수 확인 필요 
        // info!("msg: {:?}", m.to_str_radix(2).as_bytes());
    }

	// Finalize
    B = TB[&C];
    // bitshift 구현 어케함
    // *m += Mpz::from(B).mul
    // cargo Mpz::from(B).mul

    let mut exp2 = Mpz::new();
    // Mpz::mul_2exp(&mut exp2, &Mpz::from(B), op2);

    *m += Mpz::from(B) * Mpz::ui_pow_ui(2,(n-1)*s - r);
    // 이거 몇번째 비트 세팅하는거 있을텐데 
    // 비트로 읽어오는것도 있을거고
    // let mut B_ = Mpz::new_reserve(s as usize);
    // let mut Bbits = Mpz::from(B).to_str_radix(2);

    // let mpzB = Mpz::from(B);
    // for idx in 0..s {
    //     if mpzB.tstbit(idx as usize) {
    //         B_.setbit(((idx + (n-1)*s - r) % s) as usize);
    //     }
    // }
    // *m += B_;
    // *m = Mpz::from(B). << ((n-1)*s - r) as usize;

    info!("m: {:?}", *m);

    return

}

pub fn joye_libert_decrypt(
    mut m: &mut Mpz,
    c: &Mpz,
    p: &Mpz,
    y: &Mpz,
    msgsize: u32
) {
    let start_time = Instant::now();

    let mut B = Mpz::new();
    let mut D = Mpz::new();
    let mut C = Mpz::new();

    *m = Mpz::from(0);
    B = Mpz::from(1);

    let mut exp_msgsize = Mpz::new();
    let mut exp_y = Mpz::new();
    let mut neg_exp_y = Mpz::new();
    let mut p_1 = Mpz::new();

    info!("c: {:?}", *c);
    p_1 = Mpz::from(p - 1);
    // p_1 -= 1;
    info!("p: {:?}", *p);
    info!("p_1 = p - 1: {:?}", p_1);

    exp_msgsize = Mpz::ui_pow_ui(2, msgsize);
    info!("exp_msgsize: {:?}", exp_msgsize);
    exp_y = p_1.borrow() / exp_msgsize.borrow();
    neg_exp_y = Mpz::neg(exp_y.clone());
    info!("exp_y: {:?}", exp_y.borrow());
    info!("neg_exp_y: {:?}", neg_exp_y);
    D = y.clone().powm(&neg_exp_y, &p);
    C = c.clone().powm(&exp_y, &p);
    info!("C: {:?}", C);
    info!("D: {:?}", D);


    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    info!("dec setting time {:?}", elapsed_time);

    let mut z = Mpz::new();
    let mut exp_c = Mpz::new();

	// Decryption 
    let mut cnt = 0;
    let total = Instant::now();

    for j in 1..msgsize {
        let start_time = Instant::now();

        exp_c = Mpz::ui_pow_ui(2, msgsize - j);
        z = C.powm(&exp_c, &p); // bitbybit 에서 TC 계산과 동일부 
        // z = C.powm(&exp_c, &p);
        cnt += 1;
        // info!("z: {:?}", z);

        if z != Mpz::one() {
            // info!("z != 1");
            *m += B.borrow();
            C *= D.clone();
            C %= p.clone();
        }

        B += B.clone(); // B = 2*B - 비트 자리수 하나씩 올리는거 
        D = D.clone() * D.clone();
        D %= p.clone(); //.powm(&Mpz::from(2), &p);
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        // info!("elapsed_time {:?}", elapsed_time);
        total.checked_add(elapsed_time);
    }

    // println!("avg {:?}", total.into() / cnt);
    info!("avg {:?}", total);

    info!("C: {:?}", C);
    info!("exp_cnt: {:?}",cnt);


	// Finalize
    if C != Mpz::one() {
	    info!("C != 1");
        *m += B.clone();
	    info!("m: {:?}", *m);
    }


    return

}



pub fn joye_libert_exp(
    mut g: &mut Mpz,
    mut res: &mut Mpz,
    p: &Mpz,
    y: &Mpz,
    msgsize: u32
) {
    let mut B = Mpz::new();
    let mut D = Mpz::new();
    let mut C = Mpz::new();

    B = Mpz::from(1);

    let mut exp_msgsize = Mpz::new();
    let mut exp_y = Mpz::new();
    let mut neg_exp_y = Mpz::new();
    let mut p_1 = Mpz::new();

    p_1 = Mpz::from(p.clone());
    p_1 -= 1;
    info!("p: {:?}", p);
    info!("p_1 = p - 1: {:?}", p_1);

    exp_y = p_1.clone() / Mpz::from(2);

    *res = g.powm(&exp_y, &p);
    
}


pub fn joye_libert_exp_n2(
    mut g: &mut Mpz,
    mut res: &mut Mpz,
    p: &Mpz,
    q: &Mpz,
    N: &Mpz,
) {

    let mut phi_N = p.clone() * q.clone();

    *res = g.powm(&phi_N, &N);
    
}

