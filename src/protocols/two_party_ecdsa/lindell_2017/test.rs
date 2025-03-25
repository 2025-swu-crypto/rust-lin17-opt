// For integration tests, please add your tests in /tests instead

use std::hash::BuildHasherDefault;

use crate::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use crate::utilities::zk_pdl::ZkPdlError;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{BasicOps, Integer, Modulo, Converter};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};

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
fn test_two_party_sign() {
    // assume party1 and party2 engaged with KeyGen in the past resulting in
    // party1 owning private share and paillier key-pair
    // party2 owning private share and paillier encryption of party1 share
    let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();

    let keypair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

    // creating the ephemeral private shares:

    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();
    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");

    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
    let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
    let message = BigInt::from(1234);
    let partial_sig = party_two::PartialSig::compute(
        &keypair.ek,
        &keypair.encrypted_share,
        &party2_private,
        &eph_ec_key_pair_party2,
        &eph_party_one_first_message.public_share,
        &message,
    );

    let party1_private = party_one::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);

    let signature = party_one::Signature::compute(
        &party1_private,
        &partial_sig.c3,
        &eph_ec_key_pair_party1,
        &eph_party_two_second_message.comm_witness.public_share,
    );

    let pubkey =
        party_one::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
    party_one::verify(&signature, &pubkey, &message).expect("Invalid signature")
}


// ------------------------- jah ------------------------ //

// ---- C.3.1 ZKPoKQR ---- //

use curv::BigInt;
use sha2::{Sha256, Digest};
use paillier::{Paillier, KeyGeneration, EncryptionKey, DecryptionKey};

#[derive(Debug, Clone)]
pub struct ZKPoKQR {
    pub n0: BigInt, //modulus n0 P1 keypair pk
    pub x: BigInt, // witness used in proof
    pub h: BigInt, // h = x^2 mod n0
    pub r: BigInt,
}

impl ZKPoKQR {
        // generate random r and compute r^2 = a
    pub fn generate_commitment(&self) -> (BigInt, BigInt) {

        let r = BigInt::sample_below(&self.n0); // r \in Z_{n0}

        let a = BigInt::mod_pow(&r, &BigInt::from(2), &self.n0); // a = r^2 mod n0
        
        (r, a) // return (r, a)
    }

    pub fn generate_challenge(&self, a: &BigInt) -> BigInt {

        let mut hasher = Sha256::default();

        hasher.update(&a.to_string().as_bytes());
        hasher.update(&self.h.to_string().as_bytes());
        
        let result_a_h = hasher.finalize();
        let last_byte = result_a_h[result_a_h.len() - 1];

        let e = if last_byte & 1 == 1{
            BigInt::from(1)
        } else {
            BigInt::from(0)
        };
        // println!("Generated e: {}", e);

        e
    }

    pub fn generate_respond(&self, r: &BigInt, e: &BigInt) -> BigInt {
        // z = x^e * r mod n0
        let x_e = BigInt::mod_pow(&self.x, e, &self.n0);

        let z: BigInt = BigInt::mod_mul(&x_e, &r, &self.n0);

        z // return z
    }

    pub fn verification(&self, a: &BigInt, e: &BigInt, z: &BigInt) -> bool {
        // lhs = z^2 mod n0
        let lhs = BigInt::mod_pow(z, &BigInt::from(2), &self.n0);

        // rhs = h^e * a mod n0
        // let h = BigInt::mod_pow(&self.x, &BigInt::from(2), &self.n0);
        let h_e = BigInt::mod_pow(&self.h, e, &self.n0);
        let rhs = BigInt::mod_mul(&h_e, &a, &self.n0);
        
        println!("lsh:{}\n rhs:{}", lhs, rhs);

        lhs == rhs
    }
}

fn zkpok_qr(proof: &ZKPoKQR) { // appendix C.3.1
    
    let (r, a) = proof.generate_commitment();
    let e = proof.generate_challenge(&a);
    let z = proof.generate_respond(&r, &e);
    let r = r.clone();

    let verified = proof.verification(&a, &e, &z);

    #[cfg(debug_assertions)]
    println!("Verification result: {}", verified);
    //println!("n0: {},\n x: {},\n h: {},\n proof: {:?},\n r: {},\n a: {},\n e: {},\n z: {}", n0, x, h, proof, r, a, e, z);
    assert_eq!(true, verified);
}


// ---- C.3.2 ZKPoKQR ---- //
#[derive(Debug, Clone)]
pub struct ZKPoKQRdl {
    pub proof: ZKPoKQR,
    pub g: BigInt,
    pub alpha: BigInt,
}

impl ZKPoKQRdl {
    pub fn generate_commitment_dl(&self) -> (BigInt, BigInt) {
        let s: u32 = 128;
        let range_upper = (BigInt::from(2).pow(s-1) * &self.proof.n0);
        let beta = BigInt::sample_range(&BigInt::from(1), &range_upper) * 2;
        let a = BigInt::mod_pow(&self.proof.h, &beta, &self.proof.n0);

    (beta, a)
    }

    pub fn generate_challenge_dl(&self, a: &BigInt) -> BigInt {
        let mut hasher = Sha256::default();

        hasher.update(a.to_string().as_bytes());
        hasher.update(&self.g.to_string().as_bytes());

        let result_a_g = hasher.finalize();
        let last_byte = result_a_g[result_a_g.len() - 1];

        let e = if last_byte & 1 ==1{
            BigInt::from(1)
        } else {
            BigInt::from(0)
        };

        e
    }

    pub fn generate_respond_dl(&self, e: &BigInt, alpha: &BigInt, beta: &BigInt) -> BigInt {
        // z = e * alpha + beta (as integer)
        let z = e * alpha + beta;

        z
    }

    pub fn verification_dl(&self, a: &BigInt, e: &BigInt, z: &BigInt) -> bool {
        
        // lhs = h^z mod n0
        let lhs = BigInt::mod_pow(&self.proof.h, z, &self.proof.n0);

        // rhs = g^e * a mod n0
        let rhs = BigInt::mod_mul(
            &BigInt::mod_pow(&self.g, e, &self.proof.n0),
            &a, 
            &self.proof.n0);
        
        // lhs.eq(&rhs)
        lhs == rhs
    }
}

fn zkpok_qrdl(proof: &ZKPoKQR) -> ZKPoKQRdl {

    let alpha = BigInt::sample_below(&proof.n0);
    let g = BigInt::mod_pow(&proof.h, &alpha, &proof.n0);

    let proof_dl: ZKPoKQRdl = ZKPoKQRdl {
        proof: proof.clone(),
        g,
        alpha,
    };

    let (beta, a) = proof_dl.generate_commitment_dl();
    let e = proof_dl.generate_challenge_dl(&a);
    let z = proof_dl.generate_respond_dl(&e, &proof_dl.alpha, &beta);

    #[cfg(debug_assertions)]
    let verified_dl = proof_dl.verification_dl(&a, &e, &z);
    println!("verification_dl result: {}", verified_dl);
    assert_eq!(true, verified_dl);

    proof_dl
}

// ---- C.3.3 ZKPoKQR ---- //
pub struct ZKPoKRPwR {
    pub proof: ZKPoKQR, // n0, x, h, r
    pub proof_dl: ZKPoKQRdl, // g, alpha
    pub y: BigInt,
    pub rd: BigInt,
    pub beta: BigInt,
    pub n: BigInt, 
    pub p: BigInt,
    pub q: BigInt,
    pub n_square: BigInt,
}

impl ZKPoKRPwR {

     pub fn p1_1st_msg(&self) -> (BigInt, BigInt, BigInt) {

            // capital_c = g^x * h^alpha mod n0
        let capital_c = BigInt::mod_mul(
            &BigInt::mod_pow(&self.proof_dl.g, &self.proof.x, &self.proof.n0),
            &BigInt::mod_pow(&self.proof.h, &self.proof_dl.alpha, &self.proof.n0),
            &self.proof.n0
        );

            // d = rd^n * (1 + n)^y mod n_square
        let d = BigInt::mod_mul(
            &BigInt::mod_pow(&self.rd, &self.n, &self.n_square),
            &BigInt::mod_pow(&(BigInt::from(1) + &self.n), &self.y, &self.n_square),
            &self.proof.n0
        );

            // capital_d = g^y * h^beta mod n0
        let capital_d = BigInt::mod_mul(
            &BigInt::mod_pow(&self.proof_dl.g,&self.y, &self.proof.n0),
            &BigInt::mod_pow(&self.proof.h, &self.beta, &self.proof.n0),
            &self.proof.n0
        );

        (capital_c, d, capital_d)
        }

     pub fn generate_challenge_rpwr(&self, capital_c: &BigInt, d: &BigInt, capital_d: &BigInt, t: u32) -> BigInt { // e <- Z_{2^t}
        let mut hasher = Sha256::default();

        hasher.update(capital_c.to_string().as_bytes());
        hasher.update(d.to_string().as_bytes());
        hasher.update(capital_d.to_string().as_bytes());

        let result_cdd = hasher.finalize();
        let modulus = BigInt::from(2).pow(t);
        let e: BigInt = BigInt::modulus(&BigInt::from_bytes(&result_cdd), &modulus);

        e
     }
    
    pub fn p1_2nd_msg(&self, e: &BigInt) -> (BigInt, BigInt, BigInt) {
        let z1 = &self.y + (e * &self.proof.x); // as integer
        let z2 = BigInt::mod_mul(
            &self.rd, 
            &BigInt::mod_pow(&self.proof.r, e, &self.n), 
            &self.n
        );
        let z3 = &self.beta + (&self.proof_dl.alpha * e);

        (z1, z2, z3)
    }

    pub fn verification_rpwr(&self, 
        z1: &BigInt, 
        z2: &BigInt, 
        z3: &BigInt, 
        d: &BigInt, 
        e: &BigInt, 
        capital_d: &BigInt, 
        capital_c: &BigInt,
        t: u32, 
        l: u32,
        // z4: &BigInt // 뭘 z4로 계산해둬야 하는 걸까??
    ) -> (bool, bool, /*bool*/){

        let c = BigInt::mod_mul(
            &BigInt::mod_pow(&self.proof.r, &self.n, &self.n_square),
            &BigInt::mod_pow(&(BigInt::from(1) + &self.n), &self.proof.x, &self.n_square),
            &self.n_square
            );
        
        let lhs1 = BigInt::mod_mul(
            &BigInt::mod_pow(z2, &self.n, &self.n_square),
            &BigInt::mod_pow(&(BigInt::from(1) + &self.n), z1, &self.n_square),
            &self.n_square
            );
        let rhs1 = BigInt::mod_mul(
            d,
            &BigInt::mod_pow(&c, e, &self.n_square), 
            &self.n_square
        );

        let lhs2 = BigInt::mod_mul(
            &BigInt::mod_pow(&self.proof_dl.g, z1, &self.proof.n0), 
            &BigInt::mod_pow(&self.proof.h, z3, &self.proof.n0),
            &self.proof.n0
        );

        let rhs2 = BigInt::mod_mul(
            capital_d,
            &BigInt::mod_pow(capital_c, e, &self.proof.n0),
            &self.proof.n0
        );

        // let bound_lower = BigInt::from(2).pow(t) * &self.q;
        // let bound_upper = BigInt::from(2).pow(t+l) * &self.q;
        // let verification3 = z4 >= &bound_lower && z4 < &bound_upper;

        (lhs1 == rhs1, lhs2 == rhs2, /*verification3*/)

    }
}

fn zkpok_rpwr(proof: &ZKPoKQR, proof_dl: &ZKPoKQRdl,) {
    
        // keypair for P2
    let (ek2, dk2) = Paillier::keypair_with_modulus_size(3072).keys();

    let n = ek2.n.clone();
    let p = dk2.p.clone();
    let q = dk2.q.clone();
    let n_square = n.clone() * n.clone();

    let t:u32 = 128;
    let l:u32 = 80;

    let beta = BigInt::sample_below(&(BigInt::from(2).pow(t+l) * &proof.n0));
    let y = BigInt::sample_below(&(BigInt::from(2).pow(t+l) * &q));
    let rd = BigInt::sample_below(&n);

    let proof_rpwr: ZKPoKRPwR = ZKPoKRPwR {
        proof: proof.clone(),
        proof_dl: proof_dl.clone(),
        y,
        rd,
        beta,
        n,
        p,
        q,
        n_square,
    };

    let (capital_c, d, capital_d) = proof_rpwr.p1_1st_msg();
    let e = proof_rpwr.generate_challenge_rpwr(&capital_c, &d, &capital_d, t);
    let (z1, z2, z3) = proof_rpwr.p1_2nd_msg(&e);

    let verified_rpwr = proof_rpwr.verification_rpwr(&z1, &z2, &z3, &d, &e, &capital_d, &capital_c, t, l, /*z4*/);
    println!("verification_rpwr result: {:?}", verified_rpwr);

}

fn create_proof() -> (ZKPoKQR, EncryptionKey, DecryptionKey) {
    let (ek, dk) = Paillier::keypair_with_modulus_size(3072).keys();
    
    let n0 = ek.n.clone();
    let x = BigInt::sample_below(&(dk.q.clone() / BigInt::from(3)));
    let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);

    let r = BigInt::sample_below(&n0); // r \in Z_{n0}
    (ZKPoKQR {n0, x, h, r}, ek, dk)
}

#[test]
fn test_zkp() {
    let (proof, _, _) = create_proof();
    let proof_dl = zkpok_qrdl(&proof);
    zkpok_qr(&proof);
    zkpok_qrdl(&proof);
    zkpok_rpwr(&proof, &proof_dl);
}