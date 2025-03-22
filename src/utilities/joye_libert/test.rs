use std::borrow::Borrow;
use std::cmp::{Ordering};
use std::io::Write;
use std::mem::{size_of, size_of_val};
use std::ops::Neg;
use std::{marker::PhantomData, time::Instant};
use std::fs::{self, OpenOptions};
use std::fs::File;
use std::collections::HashMap;

use gmp::mpz::{Mpz, ProbabPrimeResult};
use gmp::rand::RandState;
use sha2::digest::generic_array::typenum::Equal;

use crate::utilities::joye_libert::joye_libert;

use super::joye_libert::{joye_libert_keygen, joye_libert_encrypt, joye_libert_decrypt, joye_libert_exp, joye_libert_exp_n2, joye_libert_decrypt_bbb};


#[cfg(not(test))] 
use log::{info, warn}; // Use log crate when building application
 
#[cfg(test)]
use std::{println as info, println as warn};


// #[test]
// fn joye_op_test() {
//     let mut f = OpenOptions::new().append(true).open("exp_data").expect("cannot open file");
//     env_logger::init();

//     f.write_all(format!("\n").as_bytes()).expect("write failed");


//     let mut N: Mpz = Mpz::new();
//     let mut y: Mpz = Mpz::new();
//     let mut p: Mpz = Mpz::new();


//     let mut state: RandState = RandState::new();

//     // 실제 사이즈로 수정한 상태 
//     let msgsize: u32 = 768;
//     let msgsize_mpz = Mpz::from(2).pow(msgsize);
//     let keysize: u32 = 3200;

//     info!("start keygen");
//     let start_time = Instant::now();
//     joye_libert_keygen(&mut N, &mut y, &mut p, msgsize, keysize);
//     info!("N: {:?}", N);
//     info!("y: {:?}", y);
//     info!("p: {:?}", p);

//     let end_time = Instant::now();
//     let elapsed_time = end_time.duration_since(start_time);

//     let mut g: Mpz = RandState::urandom(&mut state, &msgsize_mpz);
//     let mut res = Mpz::new();

//     info!("start exponentiation");
//     let start_time = Instant::now();
//     joye_libert_exp(&mut g, &mut res, &p, &y, msgsize);
//     let end_time = Instant::now();
//     let elapsed_time = end_time.duration_since(start_time);
//     f.write_all(format!("exponentiation time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

    
// }


#[test]
fn joye_libert() {
    let mut f = OpenOptions::new().append(true).open("exp_data").expect("cannot open file");
    // f.write_all(format!("\n\nlambda bit: {:?}\n", lambda).as_bytes()).expect("write failed");
    let mut f2 = OpenOptions::new().append(true).open("primes").expect("cannot open file");

    let p_str: Vec<String> = fs::read_to_string("primes")
                    .unwrap()  // panic on possible file-reading    errors
                    .lines()  // split the string into an iterator of string slices
                    .map(String::from)  // make each slice into a string
                    .collect();  // gather them together into a vector;


    env_logger::init();



    let mut N: Mpz = Mpz::new();
    let mut y: Mpz = Mpz::new();
    let mut p: Mpz = Mpz::new();
    let mut q: Mpz = Mpz::new();


    let mut state: RandState = RandState::new();

    // 실제 사이즈로 수정한 상태 
    let msgsize: u32 = 768;
    let msgsize_mpz = Mpz::from(2).pow(msgsize);
    let keysize: u32 = 3200;

    // info!("start keygen");
    // let start_time = Instant::now();
    // joye_libert_keygen(&mut N, &mut y, &mut p, msgsize, keysize);
    // info!("N: {:?}", N);
    // info!("y: {:?}", y);
    // info!("p: {:?}", p);
    
    if p_str.len() == 0 {
        info!("start keygen");
        let start_time = Instant::now();
        joye_libert_keygen(&mut N, &mut y, &mut p, &mut q, msgsize, keysize);
        info!("N: {:?}", N);
        info!("N-bit: {:?}", N.bit_length());
        info!("y: {:?}", y);
        info!("p: {:?}", p);
    
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        f.write_all(format!("keygen time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
        f2.write_all(N.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
        f2.write_all(y.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
        f2.write_all(p.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
        f2.write_all(q.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
    } else {
        N = Mpz::from_str_radix(&p_str[0], 10).unwrap();
        y = Mpz::from_str_radix(&p_str[1], 10).unwrap();
        p = Mpz::from_str_radix(&p_str[2], 10).unwrap();
    }

    let mut m1: Mpz = RandState::urandom(&mut state, &msgsize_mpz);
    let mut m2: Mpz = RandState::urandom(&mut state, &msgsize_mpz);
    let mut m3: Mpz = RandState::urandom(&mut state, &msgsize_mpz);
    // let mut m1: Mpz = Mpz::from(999);
    // let mut m2: Mpz = Mpz::from(150);
    // let mut m3: Mpz = Mpz::from(777);
    let mut s1: Mpz = RandState::urandom(&mut state, &Mpz::ui_pow_ui(2,256 )); //Mpz::from(10);

    let mut c1: Mpz = Mpz::new();
    let mut c2: Mpz = Mpz::new();
    let mut c3: Mpz = Mpz::new();

    let mut state: RandState = RandState::new();

	info!("Testing the additively homomorphic property\n");
    println!("m1: {:?}", m1);
    println!("m2: {:?}", m2);

    let start_time = Instant::now();
    joye_libert_encrypt(&mut c1, &mut state, &m1, &y, &N, msgsize);
	let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    f.write_all(format!("enc time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

    let mut recov_m1 = Mpz::new();
    let start_time = Instant::now();
    joye_libert_decrypt(&mut recov_m1, &c1, &p, &y, msgsize);
	info!("m1 {:?}", m1);
	info!("recov_m1 {:?}", recov_m1);
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);


    f.write_all(format!("decrypt time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    assert_eq!(m1, recov_m1);
	
    // return;
    joye_libert_encrypt(&mut c2, &mut state, &m2, &y, &N, msgsize);

    println!("c1 in test: {:?}", c1);
    // additive test
    let start_time = Instant::now();
    c1 = c1.borrow() * c2.borrow() % N.borrow();
    println!("c1 in test: {:?}", c1);
    // c1 %= N.clone();
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);

    let mut recov_m = Mpz::new();

    println!("c1 in test: {:?}", c1);

	joye_libert_decrypt(&mut recov_m, &c1, &p, &y, msgsize);
    

    f.write_all(format!("addition time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
	info!("recov_m = m1 + m2: {:?}", recov_m);
	info!("m1 + m2: {:?}", m1 + m2);



	info!("m3: {:?}", m3);
    joye_libert_encrypt(&mut c3, &mut state, &m3, &y, &N, msgsize);

    // println!("c1 in test: {:?}", c1);
    // scalar mul test
    let start_time = Instant::now();
    c3 = c3.powm(&s1, &N);
    // println!("c1 in test: {:?}", c1);
    // c1 %= N.clone();
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);


    let mut recov_m = Mpz::new();

    info!("c3 in test: {:?}", c3);

	joye_libert_decrypt(&mut recov_m, &c3, &p, &y, msgsize);
    
    f.write_all(format!("scalar mult time: {:?}\n\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
	info!("recov_m = m1 + m2: {:?}", recov_m);
	info!("m3 * s1: {:?}", m3.clone() * s1.clone());

    assert_eq!(m3.clone()*s1.clone(), recov_m.clone());


}

#[test]
fn joye_libert_precom(){

    let mut f = OpenOptions::new().append(true).open("precom_data").expect("cannot open file");
    let mut f2 = OpenOptions::new().append(true).open("primes").expect("cannot open file");

    let p_str: Vec<String> = fs::read_to_string("primes")
                    .unwrap()  // panic on possible file-reading    errors
                    .lines()  // split the string into an iterator of string slices
                    .map(String::from)  // make each slice into a string
                    .collect();  // gather them together into a vector;

    let mut N: Mpz = Mpz::new();
    let mut y: Mpz = Mpz::new();
    let mut p: Mpz = Mpz::new();
    let mut q: Mpz = Mpz::new();


    let mut state: RandState = RandState::new();

    // keygen
    // msgsize == k
    // keysize == lambda?
    let k: u32 = 768;
    // let k: u32 = 10;
    let k_pow = Mpz::from(2).pow(k);
    let keysize: u32 = 3200;


    // println!("k_pow as str_radix {:?}", k_pow.clone());

    if p_str.len() == 0 {
        info!("start keygen");
        let start_time = Instant::now();
        joye_libert_keygen(&mut N, &mut y, &mut p, &mut q, k, keysize);
        info!("N: {:?}", N);
        info!("y: {:?}", y);
        info!("p: {:?}", p);
    
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        f.write_all(format!("keygen time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
        f2.write_all(N.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
        f2.write_all(y.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
        f2.write_all(p.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
    } else {
        N = Mpz::from_str_radix(&p_str[0], 10).unwrap();
        y = Mpz::from_str_radix(&p_str[1], 10).unwrap();
        p = Mpz::from_str_radix(&p_str[2], 10).unwrap();
    }
    

    // enc
    info!("start enc");
    let start_time = Instant::now();
    let mut c: Mpz = Mpz::new();
    let mut m: Mpz = RandState::urandom(&mut state, &Mpz::from(k_pow.clone()));
    joye_libert_encrypt(&mut c, &mut state, &m, &y, &N, k);
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    f.write_all(format!("enc time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    // precom
    info!("start precom");
    let start_time = Instant::now();
    let mut TD: Vec<Mpz> = vec![Mpz::new(); (k) as usize];
    let mut d_exp = Mpz::from(p.clone()-1);
    d_exp = d_exp / k_pow.clone();
    d_exp = d_exp.neg();

    TD[(k - 1) as usize] = y.powm(&d_exp, &p);
    for i_u32 in (1..k-1).rev() {
        let i = i_u32 as usize;
        TD[i] = TD[i+1].clone() * TD[i+1].clone();
        TD[i] %= p.clone();
    }

    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    f.write_all(format!("precom time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");






    info!("start bit-by-bit dec");
    let start_time = Instant::now();
    let start_c = Instant::now();

    let mut TC: Vec<Mpz> = vec![Mpz::new(); k as usize];
    let mut c_exp = Mpz::from(p.clone()-1);
    c_exp = c_exp / k_pow.clone();

    TC[(k - 1) as usize] = c.powm(&c_exp, &p);
    for i_u32 in (0..k-1).rev() {
        let i = i_u32 as usize;
        TC[i] = TC[i+1].clone() * TC[i+1].clone();
        TC[i] %= p.clone();
    }

    let end_c = Instant::now();
    let elapsed_time_c = end_c.duration_since(start_c);
    f.write_all(format!("bit-by-bit precom c time: {:?}\n",  elapsed_time_c.as_micros()).as_bytes()).expect("write failed");
    
    // origin_dec
    // let mut recov_m1 = Mpz::new();
    // joye_libert_decrypt(&mut recov_m1, &c1, &p, &y, msgsize);



    let mut m_new = Mpz::from(0);
    
    // println!("m: {:?}", m);
    // println!("m bit_length: {:?}", m.bit_length());


    // bit-by-bit dec
    for i in 0..m.bit_length() {
        let mut c = TC[i].clone(); 
        
        if i == 0 {
            if c.cmp(&Mpz::one()) != Ordering::Equal {
                m_new.setbit(i);
                // println!("m_new: {:?}", m_new);
            }
            continue;
        }

        let start_j = Instant::now();
        for j in 0..i {
            if m_new.tstbit(j) {
                // println!("m_new tstbit: {:?}", m_new.tstbit(j));
                
                c *= TD[i - j].clone();
                c %= p.clone();
            }
        }
        let end_j = Instant::now();
        let elapsed_time_j = end_j.duration_since(start_j);
        f.write_all(format!("bit-by-bit dec - i_iter{:?} time: {:?}\n",i,  elapsed_time_j.as_micros()).as_bytes()).expect("write failed");

        println!("c: {:?}", c);
        if c != Mpz::one() {
            m_new.setbit(i);
            // println!("m_new: {:?}", m_new);
        }
    }

    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    f.write_all(format!("bit-by-bit dec time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    println!("m_new: {:?}", m_new);
    println!("m: {:?}", m);
    assert_eq!(m, m_new);

}

#[test]
fn joye_libert_precom2(){
    let mut f = OpenOptions::new().append(true).open("precom_data2").expect("cannot open file");
    let mut f2 = OpenOptions::new().append(true).open("primes").expect("cannot open file");
    let mut f3 = OpenOptions::new().write(true).open("tb_data").expect("cannot open file");
    let mut f4= OpenOptions::new().write(true).open("td_data").expect("cannot open file");

    let p_str: Vec<String> = fs::read_to_string("primes")
                    .unwrap()  // panic on possible file-reading    errors
                    .lines()  // split the string into an iterator of string slices
                    .map(String::from)  // make each slice into a string
                    .collect();  // gather them together into a vector;


    let mut N: Mpz = Mpz::new();
    let mut y: Mpz = Mpz::new();
    let mut p: Mpz = Mpz::new();
    let mut q: Mpz = Mpz::new();


    let mut state: RandState = RandState::new();

    // keygen
    // msgsize == k
    // keysize == lambda?
    let k: u32 = 768;
    // let k: u32 = 10;
    let k_pow = Mpz::from(2).pow(k);
    let keysize: u32 = 3200;

    let s:usize = 13; // 5, 10만 테스트 해보기 
    let n = k.div_ceil(s as u32) as usize;

    info!("s: {:?}, n: {:?}", s, n);
    f.write_all(format!("\n\n==== s: {:?}, n: {:?}\n", s, n).as_bytes()).expect("write failed");


    // println!("k_pow as str_radix {:?}", k_pow.clone());
 
    if p_str.len() == 0 {
        info!("start keygen");
        let start_time = Instant::now();
        joye_libert_keygen(&mut N, &mut y, &mut p, &mut q, k, keysize);
        info!("N: {:?}", N);
        info!("y: {:?}", y);
        info!("p: {:?}", p);
    
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        f.write_all(format!("keygen time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
        f2.write_all(N.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
        f2.write_all(y.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
        f2.write_all(p.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
        f2.write_all(q.to_str_radix(10).as_bytes()).expect("write failed");
        f2.write_all("\n".as_bytes()).expect("write failed");
    } else {
        N = Mpz::from_str_radix(&p_str[0], 10).unwrap();
        y = Mpz::from_str_radix(&p_str[1], 10).unwrap();
        p = Mpz::from_str_radix(&p_str[2], 10).unwrap();
    }
    

    // enc
    info!("start enc");
    let start_time = Instant::now();
    let mut c: Mpz = Mpz::new();
    let mut m: Mpz = RandState::urandom(&mut state, &Mpz::from(k_pow.clone()));
    f.write_all(format!("msg_base 10 \n").as_bytes()).expect("write failed");
    f.write_all( m.to_str_radix(10).as_bytes()).expect("write failed");
    f.write_all(format!("\n").as_bytes()).expect("write failed");
    f.write_all(format!("msg_bits \n").as_bytes()).expect("write failed");
    f.write_all(m.to_str_radix(2).as_bytes()).expect("write failed");
    f.write_all(format!("\n", ).as_bytes()).expect("write failed");

    joye_libert_encrypt(&mut c, &mut state, &m, &y, &N, k);
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    f.write_all(format!("enc time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    // precom
    info!("start precom");
    let start_time = Instant::now();

    info!("p: {:?}", p);

    // 추후 파일 저장으로 변환
    // let mut TB: Vec<Mpz> = vec![Mpz::new(); (k) as usize];
    let mut s_pow = Mpz::ui_pow_ui(2, s as u32);
    s_pow =  Mpz::from(p.clone()-1) / s_pow;
    let mut start = y.powm(&s_pow, &p);
    let mut key = Mpz::one().clone();
    let mut TB: HashMap<Mpz, u32> = HashMap::new();
    // from([
    //     (Mpz::one().clone(), 0),
    //     (start.clone(), 1),
    // ]);

    // f.write_all(format!("TB start size: {:?}\n", size_of_val(&start)).as_bytes()).expect("write failed");
    // f.write_all(format!("TB init size: {:?}\n", size_of_val(&TB)).as_bytes()).expect("write failed");
    // f.write_all(format!("TB init len: {:?}\n", TB.len()).as_bytes()).expect("write failed");
    
    // 2^s 계산 확인
    for i in 0..(2 as u32).pow(s as u32) {//.rev() {
        TB.insert(key.clone(), i);
        // info!("test {:?}", TB[&key]);
        f3.write_all(key.to_str_radix(10).as_bytes()).expect("write failed");
        f3.write_all("\n".as_bytes()).expect("write failed");
        key *= start.clone();
        key %= p.clone();
        
    }

    // let mut TB_ = TB.clone();
    f.write_all(format!("TB end len: {:?}\n", TB.len()).as_bytes()).expect("write failed");


    // info!("tb len {:?}", TB.len());
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    f.write_all(format!("precom TB time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
    f.write_all(format!("tb len {:?}\n", TB.len()).as_bytes()).expect("write failed");



    info!("start TD precom dec");
    let start_time = Instant::now();
    let start_c = Instant::now();

    let mut TD: Vec<Mpz> =  vec![Mpz::new(); n*(2_usize.pow(s as u32))]; // (0..n).map(|i| &TD[i]).collect();
    // let mut TD: Vec<HashMap<u32, Mpz>> = vec![HashMap::new(); n];
    
    let mut h_start = Mpz::ui_pow_ui(2, k);
    h_start = Mpz::from(p.clone()-1) / h_start;
    h_start = y.powm(&h_start.neg(), &p);


    // let mut key = Mpz::new();

    for j in 0..n-1 {
        let j_u32 = j as u32;
        let mut start = h_start.powm(&Mpz::ui_pow_ui(2, j_u32*(s as u32).clone()), &p);
        key = Mpz::one().clone();
        for i in 0..2_usize.pow(s as u32) {
            TD[2_usize.pow(s as u32) * j  + i] =  key.clone();
            f4.write_all(key.to_str_radix(10).as_bytes()).expect("write failed");
            f4.write_all("\n".as_bytes()).expect("write failed");
            key = (key.clone() * start.clone()) % p.clone();
        }
    }


    let end_c = Instant::now();
    let elapsed_time_c = end_c.duration_since(start_c);
    f.write_all(format!("bit-by-bit precom TD time: {:?}\n",  elapsed_time_c.as_micros()).as_bytes()).expect("write failed");
    
    // origin_dec
    // let mut recov_m1 = Mpz::new();
    // joye_libert_decrypt(&mut recov_m1, &c1, &p, &y, msgsize);


    // bit-by-bit dec
    info!("start bit-by-bit dec");
    let start_time = Instant::now();
    let mut m_new = Mpz::from(m.clone());
    // m_new = m.clone() * Mpz::zero();
    info!("m_new bitlen {:?}",m_new.bit_length());
    info!("m_new bitlen {:?}",m_new);
    // m_new.set_len(1000);
    // info!("m_new bitlen {:?}",m_new.bit_length());
    joye_libert_decrypt_bbb(&mut m_new, &c, &p, &y, k, n as u32, s as u32, TB.clone(), &TD);

    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    f.write_all(format!("bit-by-bit dec time: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    info!("m_new: {:?}", m_new);
    info!("m: {:?}", m);
    assert_eq!(m, m_new);

}