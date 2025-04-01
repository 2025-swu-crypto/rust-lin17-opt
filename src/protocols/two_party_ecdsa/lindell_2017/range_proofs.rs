// use curv::BigInt;
// use curv::arithmetic::One;
// use curv::arithmetic::Zero;
// use curv::arithmetic::traits::Samplable;
// use curv::arithmetic::{BasicOps, Integer, Modulo, Converter};

// use sha2::{Sha256, Digest};
// use paillier::{Paillier, KeyGeneration, EncryptionKey, DecryptionKey};
// use zk_paillier::zkproofs::DLogStatement;

// use crate::utilities::zk_pdl::{Prover, Verifier};
// use crate::utilities::zk_pdl_with_slack::commitment_unknown_order;

// #[derive(Debug, Clone)]
// pub struct ZKProver {
//     n0: BigInt,
//     x: BigInt,
//     r: BigInt,
// }

// impl ZKProver {
//     pub fn new(modulus: &BigInt, q: &BigInt) -> Self {
//         let x = BigInt::sample_below(&(q / BigInt::from(3))); // witness
//         let r = BigInt::sample_below(modulus); // blinding_r
//         Self {
//             n0: modulus.clone(),
//             x, 
//             r,
//         }
//     }

//     pub fn compute_h(&self) -> BigInt {
//         let h: BigInt = BigInt::mod_pow(&self.x, &BigInt::from(2), &self.n0);
//         h
//     }

//     pub fn generate_commitment(&self) -> BigInt {

//         let a: BigInt = BigInt::mod_pow(&self.r, &BigInt::from(2), &self.n0); // a = r^2 mod n0
        
//         a
//     }

//     pub fn generate_challenge(&self, a: &BigInt, h: &BigInt) -> BigInt {

//         let mut hasher = Sha256::default();

//         hasher.update(a.to_string().as_bytes());
//         hasher.update(h.to_string().as_bytes());
        
//         let result_a_h = hasher.finalize();
//         let last_byte = result_a_h[result_a_h.len() - 1];

//         let e = if last_byte & 1 == 1{
//             BigInt::from(1)
//         } else {
//             BigInt::from(0)
//         };
//         // println!("Generated e: {}", e);

//         e
//     }

//     pub fn generate_respond(&self, e: &BigInt) -> BigInt {
//         // z = x^e * r mod n0
//         let x_e = BigInt::mod_pow(&self.x, e, &self.n0);

//         let z: BigInt = BigInt::mod_mul(&x_e, &self.r, &self.n0);

//         z
//     }
// }

// pub struct ProofQR {
//     a: BigInt,
//     z: BigInt,
// }

// pub struct VerifierQR{}

// impl VerifierQR {
//     pub fn verification(&self, n0: &BigInt, h: &BigInt, a: &BigInt, z: &BigInt) -> bool {
        
//         let mut hasher = Sha256::default();

//         hasher.update(a.to_string().as_bytes());
//         hasher.update(h.to_string().as_bytes());
            
//         let result_a_h = hasher.finalize();
//         let last_byte = result_a_h[result_a_h.len() - 1];
    
//         let e = if last_byte & 1 == 1{
//             BigInt::from(1)
//         } else {
//             BigInt::from(0)
//         };
//             // lhs = z^2 mod n0
//         let lhs = BigInt::mod_pow(z, &BigInt::from(2), n0);

//         // rhs = h^e * a mod n0
//         // let h = BigInt::mod_pow(&self.x, &BigInt::from(2), &self.n0);
//         let h_e = BigInt::mod_pow(h, &e, n0);
//         let rhs = BigInt::mod_mul(&h_e, a, n0);
//         lhs == rhs
//     }
// }

// pub struct ZKProverdl {
//     pub prover: ZKProver,
//     pub alpha: BigInt,
//     pub g: BigInt,
// }

// pub struct ProofQRdl {
//     a: BigInt,
//     z: BigInt,
// }

// impl ZKProverdl {
//     pub fn generate_commitment_dl(&self, h: &BigInt, n0: &BigInt) -> (BigInt, BigInt) {
//         let s: u32 = 128;
//         let beta = BigInt::sample_range(&BigInt::from(1), &(BigInt::from(2).pow(s-1) * n0));
//         let a = BigInt::mod_pow(&h, &beta, &n0);
//         (beta, a)
//     }

//     pub fn generate_challenge_dl(&self, g: &BigInt, a: &BigInt) -> BigInt {
//         let mut hasher = Sha256::default();

//         hasher.update(a.to_string().as_bytes());
//         hasher.update(g.to_string().as_bytes());

//         let result_a_g = hasher.finalize();
//         let last_byte = result_a_g[result_a_g.len() - 1];

//         let e = if last_byte & 1 ==1{
//             BigInt::from(1)
//         } else {
//             BigInt::from(0)
//         };

//         e
//     }

//     pub fn generate_respond_dl(&self, e: &BigInt, alpha: &BigInt, beta: &BigInt) -> BigInt {
//         // z = e * alpha + beta (as integer)
//         let z = e * alpha + beta;

//         z
//     }

// }

// pub struct VerifierQRdl {}

// impl VerifierQRdl {
//     pub fn verification_dl(&self, n0: &BigInt, h: &BigInt, g: &BigInt, a: &BigInt, z: &BigInt,) -> bool {
//         let mut hasher = Sha256::default();

//         hasher.update(a.to_string().as_bytes());
//         hasher.update(g.to_string().as_bytes());

//         let result_a_g = hasher.finalize();
//         let last_byte = result_a_g[result_a_g.len() - 1];

//         let e = if last_byte & 1 ==1{
//             BigInt::from(1)
//         } else {
//             BigInt::from(0)
//         };

//         // lhs = h^z mod n0
//         let lhs_dl = BigInt::mod_pow(&h, z, &n0);

//         // rhs = g^e * a mod n0
//         let rhs_dl = BigInt::mod_mul(
//             &BigInt::mod_pow(&g, &e, &n0),
//             &a, 
//             &n0);
        
//         // lhs.eq(&rhs)
//         lhs_dl == rhs_dl
//     }
// }

// pub struct ProverRangeProof {
//     alpha: BigInt,
//     beta: BigInt,
//     y: BigInt,
//     rd: BigInt,
//     capital_c: BigInt,
//     d: BigInt,
//     capital_d: BigInt,
// }

// impl ProverRangeProof {
//     fn prover_1st_msg(&self, n0: &BigInt, t: u32, l: u32, g: &BigInt, ) -> (BigInt, BigInt, BigInt) {
//         let alpha: BigInt = BigInt::sample_below(&n0);
//         let beta: BigInt = BigInt::sample_below(&(BigInt::from(2).pow(t+l) * n0));
//         let y = BigInt::sample_below(&(BigInt::from(2).pow(t+l) * &q));
//         let rd = BigInt::sample_below(&n);
//         let capital_c = BigInt::mod_mul(
//             &BigInt::mod_pow(&g, &self.x, &self.n0),
//             &BigInt::mod_pow(&self.h, &self.alpha, &self.n0),
//             &self.n0
//         );

//             // d = rd^n * (1 + n)^y mod n_square
//         let d: BigInt = BigInt::mod_mul(
//             &BigInt::mod_pow(&self.rd, &self.n, &self.n_square),
//             &BigInt::mod_pow(&(BigInt::from(1) + &self.n), &self.y, &self.n_square),
//             &self.n_square
//         );

//             // capital_d = g^y * h^beta mod n0
//         let capital_d = BigInt::mod_mul(
//             &BigInt::mod_pow(&self.proof_dl.g,&self.y, &self.proof.n0),
//             &BigInt::mod_pow(&self.proof.h, &self.beta, &self.proof.n0),
//             &self.proof.n0
//         );

//         (capital_c, d, capital_d)
//     }
// }

// // pub fn generate_init() -> ZKProver { //jah
// //     let (ek,dk) = Paillier::keypair_safe_primes_with_modulus_size(3072).keys();
// //     let n0 = ek.n.clone();
// //     let x = BigInt::sample_below(&(dk.q.clone() / BigInt::from(3)));
// //     let r = BigInt::sample_below(&n0);

// //     ZKProver { n0, x, r }
// // }

// pub(crate) fn generate_init() -> (DLogStatement, EncryptionKey, DecryptionKey) {
//     let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
//     let one = BigInt::one();
//     let phi = (&dk_tilde.p - &one) * (&dk_tilde.q = &one);
//     let h = BigInt::sample_below(&ek_tilde.n);
//     let (xhi, _) = loop {
//         let xhi_ = BigInt::sample_below(&phi);
//         match BigInt::mod_inv(&xhi_, &phi) {
//             Some(inv) => break (xhi_, inv),
//             None => continue,
//         }
//     };
//     let g = BigInt::mod_pow(&h, &xhi, &ek_tilde.n);

//     let (ek, dk) = Paillier::keypair().keys();
//     let dlog_statement = DLogStatement {
//         g: h,
//         ni: g,
//         N: ek_tilde.n,
//     };
//     (dlog_statement, ek, dk)
// }

// #[test]
// pub fn zk_prover() -> (BigInt, BigInt, BigInt, BigInt, BigInt, DLogStatement, DLogProof) {
//     let (dlog_statement, ek, dk) = generate_init();
//     let modulus = dlog_statement.N.clone();

//     //QR proof
//     let q = &dk.q;
//     let qr_prover = ZKProver::new(&modulus, q);
//     let h = qr_prover.compute_h();
//     let (_r, a_qr) = qr_prover.generate_commitment();

// }
// // #[test]
// // fn zkp_qr() { // appendix C.3.1
// //     let prover = generate_init();
// //     println!("prover_qr = {:?}", prover);

// //     let h = prover.compute_h();
// //     let a = prover.generate_commitment();
// //     let e = prover.generate_challenge(&a, &h);
// //     let z = prover.generate_respond(&e);

// //     let proof = ProofQR { a, z };
// //     let verifier = VerifierQR {};

// //     let verified = verifier.verification(&prover.n0, &h, &proof.a, &proof.z);
// //     println!("Verification result: {}", verified);
// //     assert_eq!(true, verified);
// // }

// #[test]
// fn zkp_qrdl() { // appendix C.3.2
//     let prover = generate_init();
//     println!("prover_qrdl = {:?}", prover);

//     let h = prover.compute_h().clone();

//     let alpha: BigInt = BigInt::sample_below(&prover.n0);
//     let g: BigInt = BigInt::mod_pow(&h, &alpha, &prover.n0);
//     let prover_qrdl = ZKProverdl {
//         prover: prover.clone(),
//         alpha: alpha.clone(),
//         g: g.clone(),
//     };
//     let(beta, a) = prover_qrdl.generate_commitment_dl(&h, &prover.n0);
//     let e = prover_qrdl.generate_challenge_dl(&g, &a);
//     let z= prover_qrdl.generate_respond_dl(&e, &alpha.clone(), &beta);

//     // let proof_dl = ProofQRdl { a: a.clone(), z: z.clone() };
//     let verifier_dl = VerifierQRdl {};

//     let verified_dl = verifier_dl.verification_dl(&prover.n0, &h, &g, &a, &z);
//     println!("Verification_dl result: {}", verified_dl);
//     assert_eq!(true, verified_dl);
// }

// #[test]
// fn paillier_range_proof() { // appendix C.3.3 
//     let t: u32 = 128;
//     let s: u32 = 128;
//     let l: u32 = 80;
//     let prover = generate_init();
//     println!("prover_range_proof = {:?}", prover);
    
//     let verifier = generate_init();
//     println!("prover_range_proof = {:?}", verifier);

//     let h = prover.compute_h();
//     let g: BigInt = BigInt::mod_pow(&h, &alpha, &prover.n0);

//     let prover_range_proof = 

//     let capital_c = prover.p

//     let (alpha, beta, y, rd)
//     let (capital_c, d, capital_d)
    
//     let (z1, z2, z3)




// }