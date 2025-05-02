// For integration tests, please add your tests in /tests instead

use std::hash::BuildHasherDefault;
use curv::arithmetic::{One, Zero};
use sha2::digest::consts::U32;

use crate::protocols::two_party_ecdsa::xac_2023::{party_one, party_two};
use crate::utilities::zk_pdl::ZkPdlError;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{BasicOps, Integer, Modulo, Converter};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};

use curv::BigInt;
use sha2::{Sha256, Digest};
use paillier::{DecryptionKey, EncryptWithChosenRandomness, EncryptionKey, KeyGeneration, Mul, Paillier};


#[test]
fn test_two_party_keygen() {
    // party1 owning private share and paillier key-pair
    // party2 owning private share and paillier encryption of party1 share
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
    .expect("failed to verify commitments and DLog proof");// // // creating the ephemeral private shares:

    let capital_q = party_one_second_message.comm_witness.public_share + party_two_first_message.public_share;
    // let capital_q_bigint = BigInt::from(capital_q.);
    
}

// #[test]
// fn test_qr() {}
// #[test]
// fn test_qrdl() {}
// #[test]
// fn test_rpwr() {}