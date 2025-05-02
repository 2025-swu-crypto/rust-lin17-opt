// Party1 message , Party2 messsage 정의해야 하고, (struct & impl)
// verify 함수 사용할 수 있게 함수 선언해둬야 하고
// zkp_qr, zkp_qrdl, zkp_range_proofs, zkp_affran 마지막에 넣어줘야 한다.

use curv::arithmetic::BigInt;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::One;
use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext};
use paillier::traits::Encrypt;
use paillier::RawPlaintext;


use crate::protocols::two_party_ecdsa::lindell_2017::party_one;
use crate::utilities::mta_2021::zkp_p;
use crate::utilities::mta_2021::zkp_qr::*;
use crate::utilities::mta_2021::zkp_qrdl::*;
use crate::utilities::mta_2021::zkp_range_proof::*;
use crate::utilities::mta_2021::zkp_affine::*;



pub trait Party {
    fn setup() -> (BigInt, zkp_p::PiPProof, zkp_qr::QRProof, zkp_qrdl::QRdlProof);
}


// impl<T> Party for T{
//     fn setup() -> (BigInt, zkp_p::PiPProof, zkp_qr::QRProof, zkp_qrdl::QRdlProof) {
//         let prover = PiPProver::generate_paillier_blum_primes(3072);
//         let n = prover.n.clone();
//         // let n0 = verifier.n.clone();
//         let phi_n = (prover.get_p().clone() - BigInt::one()) * (prover.get_q().clone() - BigInt::one()); // sk = phi_n
//         let PiPProof{w, x_vec, a_vec, b_vec, z_vec} = prover.generate_pip_proof();
//         let (x, h) = qr_prover_setup(&n); // qr_statement = (x, n)
//         let QRProof {a, z} = generate_zkp_qr(&n, &x, &h);
//         let (h, g, alpha) = qrdl_prover_setup(&n);
//         let QRdlProof {a, z} = generate_zkp_qrdl(&n, &h, &g, &alpha);

//         (n, PiPProof {w, x_vec, a_vec, b_vec, z_vec}, QRProof {a: a.clone(), z: z.clone()}, QRdlProof {a, z})
//     }
// }

// pub struct PartyOne {
//     n0: BigInt, 
//     pip_proof: PiPProof,
//     qr_proof: QRProof,
//     qrdl_proof: QRdlProof, 
// }
// pub struct PartyTwo {
//     n: BigInt, 
//     pip_proof: PiPProof,
//     qr_proof: QRProof,
//     qrdl_proof: QRdlProof, 
// }

// impl PartyOne {
//     pub fn new() -> Self {
//         let (n0, pip_proof, qr_proof, qrdl_proof) = PartyOne::setup();
//         PartyOne { n0, pip_proof, qr_proof, qrdl_proof }
//     }
// }

// impl PartyTwo {
//     pub fn new() -> Self {
//         let (n, pip_proof, qr_proof, qrdl_proof) = PartyTwo::setup();
//         PartyTwo { n, pip_proof, qr_proof, qrdl_proof }
//     }

    
// }


// pub fn party_two_setup() -> (BigInt, zkp_p::PiPProof, zkp_qr::QRProof, zkp_qrdl::QRdlProof) {
//     let party_two = PiPProver::generate_paillier_blum_primes(3072);
//     let n = party_two.n.clone(); // pk = n
//     let phi_n = (party_two.get_p().clone() - BigInt::one()) * (party_two.get_q().clone() - BigInt::one()); // sk = phi_n
//     let PiPProof{w, x_vec, a_vec, b_vec, z_vec} = PiPProver::generate_pip_proof(&self);
//     let (x, h) = qr_prover_setup(&n); // qr_statement = (x, n)
//     let QRProof {a, z} = generate_zkp_qr(&n, &x, &h);
//     let (h, g, alpha) = qrdl_prover_setup(&n);
//     let QRdlProof {a, z} = generate_zkp_qrdl(&n, &h, &g, &alpha);

//     (n, PiPProof {w, x_vec, a_vec, b_vec, z_vec}, QRProof {a, z}, QRdlProof {a, z})
// }

// pub fn party_one_setup() -> (BigInt, zkp_p::PiPProof, zkp_qr::QRProof, zkp_qrdl::QRdlProof) {
//     let party_one = PiPProver::generate_paillier_blum_primes(3072);
//     let n0 = party_one.n.clone(); // pk = n
//     let phi_n0 = (party_one.get_p().clone() - BigInt::one()) * (party_one.get_q().clone() - BigInt::one()); // sk = phi_n
//     let PiPProof{w, x_vec, a_vec, b_vec, z_vec} = PiPProver::generate_pip_proof(&self);
//     let (x, h0) = qr_prover_setup(&n0);
//     let QRProof {a, z} = generate_zkp_qr(&n0, &x, &h0);
//     let (h0, g0, alpha) = qrdl_prover_setup(&n0);
//     let QRdlProof {a, z} = generate_zkp_qrdl(&n0, &h0, &g0, &alpha);

//     (n0, PiPProof {w, x_vec, a_vec, b_vec, z_vec}, QRProof {a, z}, QRdlProof {a, z})
// }


 // P2 메시지 B (party_two → party_one)
 pub struct MessageB<'b> {
    pub c_b: RawCiphertext<'b>,
    pub proof: RPwRProof, 
}

impl<'b> MessageB<'b> {
    // P2 함수: b를 Paillier로 암호화하여 메시지 생성하는 방법, 리팩토링(?)
    pub fn party_two_generate_ciphertext_b(party_two: &PiPProver,) -> MessageB {
        let n = party_two.n.clone();
        let nn = &n * &n;
        let ek = EncryptionKey::from(&n); // 또는 EncryptionKey { n, n_squared }

        let q = party_two.get_q().clone();
        let b = BigInt::sample_below(&q);
        let plaintext = RawPlaintext::from(b.clone());

        let c_b = Paillier::encrypt(&ek, plaintext);


        MessageB { 
            c_b, 
            proof, 
        }
    }
}

// pub fn generate_ciphertext() {
//     let n = 
// } -> 공통으로 쓸 수 있는 Paillier encryption function. 어딘가에 있겠지...?

 // P1 메시지 A (party_one → party_two)
pub struct MessageA<'a> {
    pub c_a: RawCiphertext<'a>,
    pub alpha: BigInt, 
    pub proof: RPwRProof,
}

impl<'a> MessageA<'a> {
    pub fn party_one_generate_ciphertext_a(party_one: &PiPProver, ) -> MessageA {
        let n = party_one.n.clone();
        let 

        MessageA { 
            c_a, 
            alpha, 
            proof: PiPProof {w, x_vec, a_vec, b_vec, z_vec} 
        }
    }
}

pub mod zkp_p;
pub mod zkp_qr;
pub mod zkp_qrdl;
pub mod zkp_range_proof;
pub mod zkp_affine;



#[test]
pub fn test_pip_proof() {
    let p1 = PartyOne::new();
    let p2 = PartyTwo::new();

    
}