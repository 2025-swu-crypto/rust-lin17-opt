use std::time::Duration;
// For integration tests, please add your tests in /tests instead
use std::{marker::PhantomData, time::Instant};
use std::io::Write;
use std::fs::{self, OpenOptions};
use std::fs::File;
use std::mem::{self, size_of};

use crate::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two, party_one_jl, party_two_jl};
// use rust_joyelibert::JoyeLibert;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{BitManipulation, Zero};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};
use curv::BigInt;
use gmp::mpz::{mpz_struct, Mpz};
use gmp::rand::RandState;


use super::paillier_test::paillier_add;
use super::party_one_jl::JoyeLibertKeyPair;
// use super::party_one_jl;

#[test]
fn test_d_log_proof_party_two_party_one() {
    let (party_one_first_message, comm_witness, _ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (party_two_first_message, _ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        comm_witness,
        &party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message,
        &party_one_second_message,
    )
    .expect("failed to verify commitments and DLog proof");
}

#[test]

fn test_full_key_gen() {
    let (party_one_first_message, comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
            Scalar::<Secp256k1>::from(&BigInt::sample(253)),
        );
    let (party_two_first_message, _ec_key_pair_party2) =
        party_two::KeyGenFirstMsg::create_with_fixed_secret_share(Scalar::<Secp256k1>::from(
            &BigInt::from(10),
        ));
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        comm_witness,
        &party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message,
        &party_one_second_message,
    )
    .expect("failed to verify commitments and DLog proof");

    // init paillier keypair:
    let paillier_key_pair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

    let party_one_private =
        party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

    let party_two_paillier = party_two::PaillierPublic {
        ek: paillier_key_pair.ek.clone(),
        encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
    };

    // zk proof of correct paillier key
    let correct_key_proof =
        party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
    party_two::PaillierPublic::verify_ni_proof_correct_key(
        correct_key_proof,
        &party_two_paillier.ek,
    )
    .expect("bad paillier key");

    //zk_pdl

    let (pdl_statement, pdl_proof, composite_dlog_proof) =
        party_one::PaillierKeyPair::pdl_proof(&party_one_private, &paillier_key_pair);
    party_two::PaillierPublic::pdl_verify(
        &composite_dlog_proof,
        &pdl_statement,
        &pdl_proof,
        &party_two_paillier,
        &party_one_second_message.comm_witness.public_share,
    )
    .expect("PDL error");
}

#[test]
fn test_two_party_sign_paillier() {
    for _ in 0..1000{

    // timer
    let mut f = OpenOptions::new().append(true).open("lin17_paillier").expect("cannot open file");
    let mut f2 = OpenOptions::new().append(true).open("result/lin17_paillier.csv").expect("cannot open file");
    // let mut f3 = OpenOptions::new().append(true).open("result/size_lin17_paillier.csv").expect("cannot open file");
    // f.write_all(format!("{:?}\n", Instant::now()).as_bytes()).expect("write failed");
    // f.write_all(format!("paillier offline runtime,").as_bytes()).expect("write failed");
    // f.write_all(format!("paillier online runtime,").as_bytes()).expect("write failed");
    // f.write_all(format!("paillier total runtime\n").as_bytes()).expect("write failed");




    let mut state: RandState = RandState::new();
    // ***** 24.12.30 TODO: 
    // ***** calc each step's time 

    // assume party1 and party2 engaged with KeyGen in the past resulting in
    // party1 owning private share and paillier key-pair
    // party2 owning private share and paillier encryption of party1 share
    
    // step 1
    let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();

    println!("com1 {:?}", _party_one_private_share_gen.pk_commitment.bit_length());


    // println!("com1-> {:?}", mem::size_of_val(&_comm_witness.pk_commitment_blind_factor));
    // println!("Mpz-> {:?}", mem::size_of::<mpz_struct>());
    // println!("proof_k_1-> {:?}", mem::size_of_val(&_comm_witness.zk_pok_blind_factor));


    
    // let start_time_paillier = Instant::now();
    let keypair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);
    // let end_time_paillier = Instant::now();
    // let elapsed_time = end_time_paillier.duration_since(start_time_paillier);
    // f.write_all(format!("paillier enc runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    // creating the ephemeral private shares:
    let start_time = Instant::now();
    let offline_start = Instant::now();

    // 3.2.2-(b)
    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();
    // 3.2.1-(a)
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();
    
    // 3.2.4-(a)
    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");

    // 3.2.3-(a)
    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
    let offline_end = Instant::now();
    let elapsed_time = offline_end.duration_since(offline_start);
    let elapsed_time_offline = elapsed_time.clone();
    f.write_all(format!("\npaillier offline runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
    f2.write_all(format!("{:?},", elapsed_time_offline.as_micros()).as_bytes()).expect("write failed");
    
    
    
    let online_start = Instant::now();
    let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
    
    // 3.2.4-(b)~(c)
    let message = BigInt::sample_range(&BigInt::zero(), &BigInt::from(2^768));//RandState::urandom(&mut state, ); //BigInt::from(1234);
    let partial_sig = party_two::PartialSig::compute(
        &keypair.ek,
        &keypair.encrypted_share,
        &party2_private,
        &eph_ec_key_pair_party2,
        &eph_party_one_first_message.public_share,
        &message,
    );

    println!("c3 {:?}", partial_sig.c3.bit_length());

    let party1_private = party_one::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);

    // 3.2.5
    let signature = party_one::Signature::compute(
        &party1_private,
        &partial_sig.c3,
        &eph_ec_key_pair_party1,
        &eph_party_two_second_message.comm_witness.public_share,
    );

    let pubkey =
        party_one::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
    party_one::verify(&signature, &pubkey, &message).expect("Invalid signature");
    let online_end = Instant::now();
    let elapsed_time = online_end.duration_since(online_start);
    let elapsed_time_online = elapsed_time.clone();
    f.write_all(format!("paillier online runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
    f2.write_all(format!("{:?},", elapsed_time_online.as_micros()).as_bytes()).expect("write failed");

    // timer
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    let elapsed_time_total = elapsed_time.clone();
    f.write_all(format!("total runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
    f2.write_all(format!("{:?}\n", elapsed_time_total.as_micros()).as_bytes()).expect("write failed");
    }
}

#[test]
fn test_two_party_sign_with_JL() {

    // timer
    let mut f = OpenOptions::new().append(true).open("lin17_JL").expect("cannot open file");
    let mut f2 = OpenOptions::new().append(true).open("result/lin17_JL.csv").expect("cannot open file");
    // f.write_all(format!("{:?}\n", Instant::now()).as_bytes()).expect("write failed");


    let mut state: RandState = RandState::new();

//     // assume party1 and party2 engaged with KeyGen in the past resulting in
//     // party1 owning private share and paillier key-pair
//     // party2 owning private share and paillier encryption of party1 share


    // PROTOCOL 3.1. KEY GENERATION PROTOCOL (p.10)
    // input: group, g, q, security param
    
    // ** 3.1.1 P1's first msg
    // output: x1, Q1, commitments, pfs of Q1 = x1*g
    let start_time_jl = Instant::now();
    let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
    party_one_jl::KeyGenFirstMsg::create_commitments();
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
    party_one_jl::EphKeyGenFirstMsg::create();
    // 3.1.1-1 P1 이 생성한 x1을 가지고? jl에 대한 keypair gen & x1의 enc 저장 // 아마...? 맞을듯 
    let keypair = JoyeLibertKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

    // f2.write_all(format!("s: {:?}", keypair..dt.s))
    println!("com1 {:?}", _party_one_private_share_gen.pk_commitment.bit_length());
    // println!("pf k_1 {:?}", mem::size_of_val(&_comm_witness.d_log_proof));

    // ** 3.1.2 P2's first msg
    // output: x2, q2, commitments, pfs of Q2 = x2*g
    let (party_two_private_share_gen, ec_key_pair_party2) = party_two_jl::KeyGenFirstMsg::create();
    
    // 오프라인으로 잡을 경우 이쪽 
    /// party1_priv: x_1, dk, dt
    let party1_private = party_one_jl::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);
    /// party2_priv: x_2
    let party2_private = party_two_jl::Party2Private::set_private_key(&ec_key_pair_party2);

    let end_time_jl = Instant::now();
    let elapsed_time = end_time_jl.duration_since(start_time_jl);
    f.write_all(format!("\njl keygen enc + dt precom runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    
    
    let start_time = Instant::now();
    let offline_start = Instant::now();
    // creating the ephemeral private shares:
    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
    party_two_jl::EphKeyGenFirstMsg::create_commitments();

    println!("R2 {:?}", mem::size_of_val(&eph_ec_key_pair_party2.public_share));
    println!("pf k_2 {:?}", mem::size_of_val(&eph_comm_witness.d_log_proof));


    // ** 3.1.4 P2's second msg
    let eph_party_two_second_message = party_two_jl::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");
    
    println!("R1 {:?}", mem::size_of_val(&eph_ec_key_pair_party1.public_share));


    // ** 3.1.3 P1's second msg
    let _eph_party_one_second_message =
        party_one_jl::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
    let offline_end = Instant::now();
    let elapsed_time = offline_end.duration_since(offline_start);
    let elapsed_time_offline = elapsed_time.clone();
    f.write_all(format!("JL offline runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
    f2.write_all(format!("{:?},", elapsed_time_offline.as_micros()).as_bytes()).expect("write failed");

    
    let online_start = Instant::now();    
    let online_start1 = Instant::now();

    let message = BigInt::sample_range(&BigInt::zero(), &BigInt::from(2^768));//RandState::urandom(&mut state, ); //BigInt::from(1234);
    
    let partial_sig = party_two_jl::PartialSig::compute(
        &keypair.ek,
        &keypair.encrypted_share,
        &party2_private,
        &eph_ec_key_pair_party2,
        &eph_party_one_first_message.public_share,
        &message,
    );

    println!("P2's partial sig {:?}", partial_sig.c3.bit_length());
    

    let online_end1 = Instant::now();
    let elapsed_time = online_end1.duration_since(online_start1);
    f.write_all(format!("JL online-p2 runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

    // // 이걸 온라인으로 잡아야하나요??
    // let mut party1_private = party_one_jl::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);

    let online_start1 = Instant::now();
    println!(">>>>>>p1 sig before: {:?}", online_start1);
    let signature = party_one_jl::Signature::compute(
        &party1_private,
        &partial_sig.c3,
        &eph_ec_key_pair_party1,
        &eph_party_two_second_message.comm_witness.public_share,
    );
    let online_end1 = Instant::now();
    println!(">>>>>>p1 sig after: {:?}", online_end1);
    let elapsed_time = online_end1.duration_since(online_start1);
    f.write_all(format!("JL online-p1 sig compute runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    let online_start1 = Instant::now();
    let pubkey =
    party_one_jl::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
    party_one_jl::verify(&signature, &pubkey, &message).expect("Invalid signature");
    let online_end1 = Instant::now();
    let elapsed_time = online_end1.duration_since(online_start1);
    f.write_all(format!("JL online-p1 sig ver runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

    let online_end = Instant::now();
    let elapsed_time = online_end.duration_since(online_start);
    let elapsed_time_online = elapsed_time.clone();
    f.write_all(format!("JL online runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
    f2.write_all(format!("{:?},", elapsed_time_online.as_micros()).as_bytes()).expect("write failed");


    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    let elapsed_time_total = elapsed_time.clone();
    f.write_all(format!("total runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
    f2.write_all(format!("{:?}\n", elapsed_time_total.as_micros()).as_bytes()).expect("write failed");
}

#[test]
fn test_jl_repeat() {

    // timer
    let mut f = OpenOptions::new().append(true).open("result/lin17_JL").expect("cannot open file");
    let mut f2 = OpenOptions::new().append(true).open("result/lin17_JL_0325.csv").expect("cannot open file");
    // f.write_all(format!("{:?}\n", Instant::now()).as_bytes()).expect("write failed");


    let mut state: RandState = RandState::new();

//     // assume party1 and party2 engaged with KeyGen in the past resulting in
//     // party1 owning private share and paillier key-pair
//     // party2 owning private share and paillier encryption of party1 share


    // PROTOCOL 3.1. KEY GENERATION PROTOCOL (p.10)
    // input: group, g, q, security param
    
    // ** 3.1.1 P1's first msg
    // output: x1, Q1, commitments, pfs of Q1 = x1*g
    let start_time_jl = Instant::now();
    let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
    party_one_jl::KeyGenFirstMsg::create_commitments();
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
    party_one_jl::EphKeyGenFirstMsg::create();
    // 3.1.1-1 P1 이 생성한 x1을 가지고? jl에 대한 keypair gen & x1의 enc 저장 // 아마...? 맞을듯 
    let keypair = JoyeLibertKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);


    for _ in 0..1000 {
        // f2.write_all(format!("s: {:?}", keypair..dt.s))
        println!("com1 {:?}", _party_one_private_share_gen.pk_commitment.bit_length());
        // println!("pf k_1 {:?}", mem::size_of_val(&_comm_witness.d_log_proof));

        // ** 3.1.2 P2's first msg
        // output: x2, q2, commitments, pfs of Q2 = x2*g
        let (party_two_private_share_gen, ec_key_pair_party2) = party_two_jl::KeyGenFirstMsg::create();

        // 오프라인으로 잡을 경우 이쪽 
        /// party1_priv: x_1, dk, dt
        let party1_private = party_one_jl::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);
        /// party2_priv: x_2
        let party2_private = party_two_jl::Party2Private::set_private_key(&ec_key_pair_party2);

        let end_time_jl = Instant::now();
        let elapsed_time = end_time_jl.duration_since(start_time_jl);
        f.write_all(format!("\njl keygen enc + dt precom runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");




        let start_time = Instant::now();
        let offline_start = Instant::now();
        // creating the ephemeral private shares:
        let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two_jl::EphKeyGenFirstMsg::create_commitments();

        println!("R2 {:?}", mem::size_of_val(&eph_ec_key_pair_party2.public_share));
        println!("pf k_2 {:?}", mem::size_of_val(&eph_comm_witness.d_log_proof));


        // ** 3.1.4 P2's second msg
        let eph_party_two_second_message = party_two_jl::EphKeyGenSecondMsg::verify_and_decommit(
            eph_comm_witness,
            &eph_party_one_first_message,
        )
        .expect("party1 DLog proof failed");

        println!("R1 {:?}", mem::size_of_val(&eph_ec_key_pair_party1.public_share));


        // ** 3.1.3 P1's second msg
        let _eph_party_one_second_message =
            party_one_jl::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &eph_party_two_first_message,
                &eph_party_two_second_message,
            )
            .expect("failed to verify commitments and DLog proof");
        let offline_end = Instant::now();
        let elapsed_time = offline_end.duration_since(offline_start);
        let elapsed_time_offline = elapsed_time.clone();
        f.write_all(format!("JL offline runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
        f2.write_all(format!("{:?},", elapsed_time_offline.as_micros()).as_bytes()).expect("write failed");


        let online_start = Instant::now();    
        let online_start1 = Instant::now();

        let message = BigInt::sample_range(&BigInt::zero(), &BigInt::from(2^768));//RandState::urandom(&mut state, ); //BigInt::from(1234);

        let partial_sig = party_two_jl::PartialSig::compute(
            &keypair.ek,
            &keypair.encrypted_share,
            &party2_private,
            &eph_ec_key_pair_party2,
            &eph_party_one_first_message.public_share,
            &message,
        );

        println!("P2's partial sig {:?}", partial_sig.c3.bit_length());


        let online_end1 = Instant::now();
        let elapsed_time = online_end1.duration_since(online_start1);
        f.write_all(format!("JL online-p2 runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

        // // 이걸 온라인으로 잡아야하나요??
        // let mut party1_private = party_one_jl::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);

        let online_start1 = Instant::now();
        println!(">>>>>>p1 sig before: {:?}", online_start1);
        let signature = party_one_jl::Signature::compute(
            &party1_private,
            &partial_sig.c3,
            &eph_ec_key_pair_party1,
            &eph_party_two_second_message.comm_witness.public_share,
        );
        let online_end1 = Instant::now();
        println!(">>>>>>p1 sig after: {:?}", online_end1);
        let elapsed_time = online_end1.duration_since(online_start1);
        f.write_all(format!("JL online-p1 sig compute runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


        let online_start1 = Instant::now();
        let pubkey =
        party_one_jl::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
        party_one_jl::verify(&signature, &pubkey, &message).expect("Invalid signature");
        let online_end1 = Instant::now();
        let elapsed_time = online_end1.duration_since(online_start1);
        f.write_all(format!("JL online-p1 sig ver runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

        let online_end = Instant::now();
        let elapsed_time = online_end.duration_since(online_start);
        let elapsed_time_online = elapsed_time.clone();
        f.write_all(format!("JL online runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
        f2.write_all(format!("{:?},", elapsed_time_online.as_micros()).as_bytes()).expect("write failed");


        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        let elapsed_time_total = elapsed_time.clone();
        f.write_all(format!("total runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
        f2.write_all(format!("{:?}\n", elapsed_time_total.as_micros()).as_bytes()).expect("write failed");
    }
    
}


#[test]
fn test_two_party_sign_with_opt() {

    // timer
    let mut f = OpenOptions::new().append(true).open("lin17_JL").expect("cannot open file");
    let mut f2 = OpenOptions::new().append(true).open("result/lin17_opt.csv").expect("cannot open file");
    // f.write_all(format!("{:?}\n", Instant::now()).as_bytes()).expect("write failed");


    let mut state: RandState = RandState::new();

//     // assume party1 and party2 engaged with KeyGen in the past resulting in
//     // party1 owning private share and paillier key-pair
//     // party2 owning private share and paillier encryption of party1 share


    // PROTOCOL 3.1. KEY GENERATION PROTOCOL (p.10)
    // input: group, g, q, security param
    
    // ** 3.1.1 P1's first msg
    // output: x1, Q1, commitments, pfs of Q1 = x1*g
    let start_time_jl = Instant::now();
    let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
    party_one_jl::KeyGenFirstMsg::create_commitments();
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
    party_one_jl::EphKeyGenFirstMsg::create();
    // 3.1.1-1 P1 이 생성한 x1을 가지고? jl에 대한 keypair gen & x1의 enc 저장 // 아마...? 맞을듯 
    let keypair = JoyeLibertKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

    println!("com1 {:?}", _party_one_private_share_gen.pk_commitment.bit_length());
    // println!("pf k1 {:?}", mem::size_of_val(&_comm_witness.d_log_proof));


    // ** 3.1.2 P2's first msg
    // output: x2, q2, commitments, pfs of Q2 = x2*g
    let (party_two_private_share_gen, ec_key_pair_party2) = party_two_jl::KeyGenFirstMsg::create();
    
    // 오프라인으로 잡을 경우 이쪽 
    /// party1_priv: x_1, dk, dt
    let party1_private = party_one_jl::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);
    /// party2_priv: x_2
    let party2_private = party_two_jl::Party2Private::set_private_key(&ec_key_pair_party2);

    let end_time_jl = Instant::now();
    let elapsed_time = end_time_jl.duration_since(start_time_jl);
    f.write_all(format!("\njl keygen enc + dt precom runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    
    
    let start_time = Instant::now();
    let offline_start = Instant::now();
    // creating the ephemeral private shares:
    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
    party_two_jl::EphKeyGenFirstMsg::create_commitments();

    // println!("R2 {:?}", mem::size_of_val(&eph_ec_key_pair_party2.public_share));
    // println!("pf k2 {:?}", mem::size_of_val(&eph_comm_witness.d_log_proof));

    // println!("R1 {:?}", mem::size_of_val(&eph_ec_key_pair_party1.public_share));



    // after: enc 타임이 offline에서 돌아감
    let partial_sig_p2 = party_two_jl::PartialSig::optimized_offline(
        &keypair.ek,
        &keypair.encrypted_share,
        &party2_private,
        &eph_ec_key_pair_party2,
        &eph_party_one_first_message.public_share,
    );

    println!("c3 {:?}", partial_sig_p2.c3.bit_length());


    let partial_sig_p1 = party_one_jl::PartialSig::optimized_offline(
        &party1_private,
        &partial_sig_p2.c3,
    );

    // ** 3.1.4 P2's second msg
    let eph_party_two_second_message = party_two_jl::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");
    
    // ** 3.1.3 P1's second msg
    let _eph_party_one_second_message =
        party_one_jl::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
    let offline_end = Instant::now();
    let elapsed_time = offline_end.duration_since(offline_start);
    let elapsed_time_offline = elapsed_time.clone();
    f.write_all(format!("JL offline runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

    
    let online_start = Instant::now();    
    let online_start1 = Instant::now();

    let message = BigInt::sample(769);
    // sample_range(&BigInt::zero(), &BigInt::ui_pow_ui(2, 769));//RandState::urandom(&mut state, ); //BigInt::from(1234);
    println!("msg: {:?}\n", message);
    // f2.write_all(format!("\n{:?},", message).as_bytes()).expect("write failed");
    
    f2.write_all(format!("\n{:?},", elapsed_time_offline.as_micros()).as_bytes()).expect("write failed");
    
    // // prev: enc 타임이 online 으로 올라감 
    // let partial_sig = party_two_jl::PartialSig::compute(
    //     &keypair.ek,
    //     &keypair.encrypted_share,
    //     &party2_private,
    //     &eph_ec_key_pair_party2,
    //     &eph_party_one_first_message.public_share,
    //     &message,
    // );

    // // after: s22 값만 p1이 받아옴
    let s22 = party_two_jl::PartialSig::optimized_online(
        &eph_ec_key_pair_party2,
        &partial_sig_p2,
        &message,
    );

    println!("s22 {:?}", s22.bit_length());


    let online_end1 = Instant::now();
    let elapsed_time = online_end1.duration_since(online_start1);
    f.write_all(format!("JL online-p2 runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


    let online_start1 = Instant::now();
    // println!(">>>>>>p1 sig before: {:?}", online_start1);
    // let signature = party_one_jl::Signature::compute(
    //     &party1_private,
    //     &partial_sig.c3,
    //     &eph_ec_key_pair_party1,
    //     &eph_party_two_second_message.comm_witness.public_share,
    // );
    let signature = party_one_jl::Signature::optimized_online(
        &party1_private,
        &partial_sig_p1.s21,
        &s22,
        &eph_ec_key_pair_party1,
        &eph_party_two_second_message.comm_witness.public_share,
    );
    let online_end1 = Instant::now();
    println!(">>>>>>p1 sig after: {:?}", online_end1);
    let elapsed_time = online_end1.duration_since(online_start1);
    f.write_all(format!("JL online-p1 sig compute runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

    // f2.write_all(format!("{:?},", signature).as_bytes()).expect("write failed");


    let online_start1 = Instant::now();
    let pubkey =
    party_one_jl::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
    party_one_jl::verify(&signature, &pubkey, &message).expect(format!("Invalid signature\nmsg: {:?}\n", message).as_str());
    let online_end1 = Instant::now();
    let elapsed_time = online_end1.duration_since(online_start1);
    f.write_all(format!("JL online-p1 sig ver runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

    let online_end = Instant::now();
    let elapsed_time = online_end.duration_since(online_start);
    let elapsed_time_online = elapsed_time.clone();
    f.write_all(format!("JL online runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
    f2.write_all(format!("{:?},", elapsed_time_online.as_micros()).as_bytes()).expect("write failed");


    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    let elapsed_time_total = elapsed_time.clone();
    f.write_all(format!("total runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
    f2.write_all(format!("{:?}", elapsed_time_total.as_micros()).as_bytes()).expect("write failed");
}

#[test]
fn test_opt_repeat() {

    // timer
    let mut f = OpenOptions::new().append(true).open("result/lin17_JL").expect("cannot open file");
    let mut f2 = OpenOptions::new().append(true).open("result/lin17_JL_opt_0325.csv").expect("cannot open file");
    // f.write_all(format!("{:?}\n", Instant::now()).as_bytes()).expect("write failed");


    let mut state: RandState = RandState::new();

//     // assume party1 and party2 engaged with KeyGen in the past resulting in
//     // party1 owning private share and paillier key-pair
//     // party2 owning private share and paillier encryption of party1 share


    // PROTOCOL 3.1. KEY GENERATION PROTOCOL (p.10)
    // input: group, g, q, security param
    
    // ** 3.1.1 P1's first msg
    // output: x1, Q1, commitments, pfs of Q1 = x1*g
    let start_time_jl = Instant::now();
    let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
    party_one_jl::KeyGenFirstMsg::create_commitments();
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
    party_one_jl::EphKeyGenFirstMsg::create();
    // 3.1.1-1 P1 이 생성한 x1을 가지고? jl에 대한 keypair gen & x1의 enc 저장 // 아마...? 맞을듯 
    let keypair = JoyeLibertKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

    println!("com1 {:?}", _party_one_private_share_gen.pk_commitment.bit_length());
    // println!("pf k1 {:?}", mem::size_of_val(&_comm_witness.d_log_proof));


    for _ in 0..1000 {
        // ** 3.1.2 P2's first msg
        // output: x2, q2, commitments, pfs of Q2 = x2*g
        let (party_two_private_share_gen, ec_key_pair_party2) = party_two_jl::KeyGenFirstMsg::create();
        
        // 오프라인으로 잡을 경우 이쪽 
        /// party1_priv: x_1, dk, dt
        let party1_private = party_one_jl::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);
        /// party2_priv: x_2
        let party2_private = party_two_jl::Party2Private::set_private_key(&ec_key_pair_party2);

        let end_time_jl = Instant::now();
        let elapsed_time = end_time_jl.duration_since(start_time_jl);
        f.write_all(format!("\njl keygen enc + dt precom runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


        
        
        let start_time = Instant::now();
        let offline_start = Instant::now();
        // creating the ephemeral private shares:
        let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two_jl::EphKeyGenFirstMsg::create_commitments();

        // println!("R2 {:?}", mem::size_of_val(&eph_ec_key_pair_party2.public_share));
        // println!("pf k2 {:?}", mem::size_of_val(&eph_comm_witness.d_log_proof));

        // println!("R1 {:?}", mem::size_of_val(&eph_ec_key_pair_party1.public_share));



        // after: enc 타임이 offline에서 돌아감
        let partial_sig_p2 = party_two_jl::PartialSig::optimized_offline(
            &keypair.ek,
            &keypair.encrypted_share,
            &party2_private,
            &eph_ec_key_pair_party2,
            &eph_party_one_first_message.public_share,
        );

        println!("c3 {:?}", partial_sig_p2.c3.bit_length());


        let partial_sig_p1 = party_one_jl::PartialSig::optimized_offline(
            &party1_private,
            &partial_sig_p2.c3,
        );

        // ** 3.1.4 P2's second msg
        let eph_party_two_second_message = party_two_jl::EphKeyGenSecondMsg::verify_and_decommit(
            eph_comm_witness,
            &eph_party_one_first_message,
        )
        .expect("party1 DLog proof failed");
        
        // ** 3.1.3 P1's second msg
        let _eph_party_one_second_message =
            party_one_jl::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &eph_party_two_first_message,
                &eph_party_two_second_message,
            )
            .expect("failed to verify commitments and DLog proof");
        let offline_end = Instant::now();
        let elapsed_time = offline_end.duration_since(offline_start);
        let elapsed_time_offline = elapsed_time.clone();
        f.write_all(format!("JL offline runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

        
        let online_start = Instant::now();    
        let online_start1 = Instant::now();

        let message = BigInt::sample(769);
        // sample_range(&BigInt::zero(), &BigInt::ui_pow_ui(2, 769));//RandState::urandom(&mut state, ); //BigInt::from(1234);
        println!("msg: {:?}\n", message);
        // f2.write_all(format!("\n{:?},", message).as_bytes()).expect("write failed");
        
        f2.write_all(format!("\n{:?},", elapsed_time_offline.as_micros()).as_bytes()).expect("write failed");
        
        // // prev: enc 타임이 online 으로 올라감 
        // let partial_sig = party_two_jl::PartialSig::compute(
        //     &keypair.ek,
        //     &keypair.encrypted_share,
        //     &party2_private,
        //     &eph_ec_key_pair_party2,
        //     &eph_party_one_first_message.public_share,
        //     &message,
        // );

        // // after: s22 값만 p1이 받아옴
        let s22 = party_two_jl::PartialSig::optimized_online(
            &eph_ec_key_pair_party2,
            &partial_sig_p2,
            &message,
        );

        println!("s22 {:?}", s22.bit_length());


        let online_end1 = Instant::now();
        let elapsed_time = online_end1.duration_since(online_start1);
        f.write_all(format!("JL online-p2 runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");


        let online_start1 = Instant::now();
        // println!(">>>>>>p1 sig before: {:?}", online_start1);
        // let signature = party_one_jl::Signature::compute(
        //     &party1_private,
        //     &partial_sig.c3,
        //     &eph_ec_key_pair_party1,
        //     &eph_party_two_second_message.comm_witness.public_share,
        // );
        let signature = party_one_jl::Signature::optimized_online(
            &party1_private,
            &partial_sig_p1.s21,
            &s22,
            &eph_ec_key_pair_party1,
            &eph_party_two_second_message.comm_witness.public_share,
        );
        let online_end1 = Instant::now();
        println!(">>>>>>p1 sig after: {:?}", online_end1);
        let elapsed_time = online_end1.duration_since(online_start1);
        f.write_all(format!("JL online-p1 sig compute runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

        // f2.write_all(format!("{:?},", signature).as_bytes()).expect("write failed");


        let online_start1 = Instant::now();
        let pubkey =
        party_one_jl::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
        party_one_jl::verify(&signature, &pubkey, &message).expect(format!("Invalid signature\nmsg: {:?}\n", message).as_str());
        let online_end1 = Instant::now();
        let elapsed_time = online_end1.duration_since(online_start1);
        f.write_all(format!("JL online-p1 sig ver runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");

        let online_end = Instant::now();
        let elapsed_time = online_end.duration_since(online_start);
        let elapsed_time_online = elapsed_time.clone();
        f.write_all(format!("JL online runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
        f2.write_all(format!("{:?},", elapsed_time_online.as_micros()).as_bytes()).expect("write failed");


        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        let elapsed_time_total = elapsed_time.clone();
        f.write_all(format!("total runtime: {:?}\n", elapsed_time.as_micros()).as_bytes()).expect("write failed");
        f2.write_all(format!("{:?}", elapsed_time_total.as_micros()).as_bytes()).expect("write failed");
    }

    
}


#[test]
fn paillier_test() {

    paillier_add();

}
