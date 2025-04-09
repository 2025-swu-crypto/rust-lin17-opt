// // use std::hash::BuildHasherDefault;

// use std::hash::BuildHasherDefault;

// use curv::BigInt;
// use curv::arithmetic::One;
// use curv::arithmetic::traits::Samplable;
// use curv::arithmetic::{BasicOps, Modulo, Converter};

// // use paillier::serialize::bigint;
// use sha2::{Sha256, Digest};

// use paillier::{KeyGeneration, Paillier};

// pub const S: u32 = 128;
// pub const T: u32 = 128;
// pub const L: u32 = 80;

// pub struct ProofQR {
//     a: BigInt,
//     z: BigInt,
// }
// pub struct ProofQRdl {
//     a: BigInt,
//     z: BigInt,
// }
// pub struct ProofRPwR {
//     capital_c: BigInt,
//     d: BigInt,
//     capital_d: BigInt,
//     z1: BigInt,
//     z2: BigInt,
//     z3: BigInt,
// }
// pub struct ProofAffRan {
//     capital_a: BigInt,
//     capital_b1: BigInt,
//     capital_b2: BigInt,
//     capital_b3: BigInt,
//     capital_b4: BigInt,
//     z1: BigInt,
//     z2: BigInt,
//     z3: BigInt,
//     z4: BigInt,
// }

// pub fn prover_init() -> (BigInt, BigInt, BigInt) {
//     let (ek, dk) = Paillier::keypair_with_modulus_size(3072).keys();
//     let n = ek.n.clone();
//     let nn = n.clone() * n.clone();
//     let q = dk.q.clone();

//     (n, nn, q)
// }

// pub fn verifier_init() -> BigInt {
//     let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
//     let n0 = ek0.n.clone();

//     n0
// }

// // appendix c.3.1
// pub fn prover_qr_setup(n0: &BigInt, )  -> (BigInt, BigInt) {
//     let x: BigInt = BigInt::sample_below(&n0);
//     let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);

//     (x, h)
// }

// pub fn verifier_qr_setup() -> BigInt {
//     let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
//     let n0 = ek0.n.clone();

//     n0
// }

// pub fn zkp_qr_prover(n0: &BigInt, h: &BigInt, x: &BigInt, ) -> ProofQR {
//     let r: BigInt = BigInt::sample_below(&n0);
//     let a = BigInt::mod_pow(&r, &BigInt::from(2), n0);

//     let mut hasher = Sha256::default();
//     hasher.update(&a.to_string().as_bytes());
//     hasher.update(&h.to_string().as_bytes()); 
//     let result = hasher.finalize();
//     let last_byte = result[result.len() - 1];
//     let e = if last_byte & 1 == 1{
//         BigInt::from(1)
//     } else {
//         BigInt::from(0)
//     };

//     let z = BigInt::mod_mul(
//         &(BigInt::mod_pow(&x, &e, n0)), 
//         &r, 
//         &n0
//     );

//     ProofQR {a, z}
// }

// pub fn zkp_qr_verifier(proof_qr: &ProofQR, n0: &BigInt, h:&BigInt, ) -> bool {
//     let ProofQR {a, z} = proof_qr; // a, z

//     let mut hasher = Sha256::default();
//     hasher.update(&proof_qr.a.to_string().as_bytes());
//     hasher.update(&h.to_string().as_bytes()); 
//     let result = hasher.finalize();
//     let last_byte = result[result.len() - 1];
//     let e = if last_byte & 1 == 1{
//         BigInt::from(1)
//     } else {
//         BigInt::from(0)
//     }; //e

//     let lhs = BigInt::mod_pow(&proof_qr.z, &BigInt::from(2), &n0); // z^2
//     let rhs = BigInt::mod_mul( // h^e * a 
//         &(BigInt::mod_pow(&h, &e, &n0)),
//         &proof_qr.a,
//         &n0,
//     );

//     println!("Verification_qr result: {}", lhs==rhs);

//     lhs == rhs

// }

// // appendix c.3.2
// pub fn prover_qrdl_setup(n0: &BigInt, ) -> (BigInt, BigInt, BigInt) {    
//     let x = BigInt::sample_below(&n0);
//     let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);

//     let alpha = BigInt::sample_below(&n0);
//     let g = BigInt::mod_pow(&h, &alpha, &n0);

//     (h, g, alpha)
// }

// pub fn verifier_qrdl_setup() -> BigInt {
//     let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
//     let n0 = ek0.n.clone();

//     n0
// }

// pub fn zkp_qrdl_prover(n0: &BigInt, h: &BigInt, g: &BigInt, alpha: &BigInt, ) -> ProofQRdl {
//     let beta = BigInt::sample_range(&BigInt::from(1), &(BigInt::from(2).pow(S-1) * n0)) * 2;
//     let a: BigInt = BigInt::mod_pow(&h, &beta, &n0); // h^beta

//     let mut hasher = Sha256::new();
//     hasher.update(a.to_string().as_bytes());
//     hasher.update(g.to_string().as_bytes());
//     let result = hasher.finalize();
//     let last_byte = result[result.len() - 1];
//     let e = if last_byte & 1 ==1{ // e
//         BigInt::from(1)
//     } else {
//         BigInt::from(0)
//     };

//     let z = e.clone() * alpha + beta; // e * alpha + beta (integer)

//     ProofQRdl {a, z}
// }

// pub fn zkp_qrdl_verifier(proof_qrdl: &ProofQRdl, n0: &BigInt, g: &BigInt, h: &BigInt, ) -> bool {
//     let ProofQRdl {a, z} = proof_qrdl;
//     let mut hasher = Sha256::new();
//     hasher.update(a.to_string().as_bytes());
//     hasher.update(g.to_string().as_bytes());
//     let result = hasher.finalize();
//     let last_byte = result[result.len() - 1];
//     let e = if last_byte & 1 ==1{ // e
//         BigInt::from(1)
//     } else {
//         BigInt::from(0)
//     };

//     let lhs = BigInt::mod_pow(&h, &proof_qrdl.z, &n0);
//     let rhs = BigInt::mod_mul(
//         &(BigInt::mod_pow(&g, &e, &n0)),
//         &proof_qrdl.a,
//         &n0,
//     );

//     println!("Verification_qrdl result: {}", lhs == rhs);

//     lhs == rhs
// }

// // appendix c.3.3
// pub fn verifier_rp_setup() -> (BigInt, BigInt, BigInt) {
//     let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
//     let n0 = ek0.n.clone();

//     let x = BigInt::sample_below(&n0);
//     let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);
//     let alpha = BigInt::sample_below(&n0);
//     let g = BigInt::mod_pow(&h, &alpha, &n0);

//     (n0, h, g)
// }

// pub fn prover_rp_setup() -> (BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, ) {
//     let (ek, dk) = Paillier::keypair_with_modulus_size(3072).keys();
//     let n = ek.n.clone();
//     let nn = n.clone() * n.clone();
//     let q = dk.q.clone();

//     let x = BigInt::sample_below(&n); // secret witness / message a, b
//     let r = BigInt::sample_below(&n); // secret witness / randomness
//     let c = BigInt::mod_mul(
//         &BigInt::mod_pow(&r, &n, &nn),
//         &BigInt::mod_pow(&(BigInt::from(1) + n.clone()), &x, &nn),
//         &nn
//     );

//     (n, nn, q, c, x, r)
// }

// pub fn zkp_range_proof_prover(
//     n0: &BigInt, 
//     n: &BigInt, 
//     nn: &BigInt, 
//     q: &BigInt, 
//     h: &BigInt, 
//     g: &BigInt, 
//     x: &BigInt, 
//     r: &BigInt, 
//     c: &BigInt, 
// ) -> ProofRPwR {
    
//     // prover's 1st message
//     let alpha = BigInt::sample_below(&n0);
//     let beta = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n0));
//     let y = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * q));
//     let rd = BigInt::sample_below(&n);
//     let capital_c = BigInt::mod_mul(
//         &BigInt::mod_pow(&g, &x, &n0),
//         &BigInt::mod_pow(&h, &alpha, &n0),
//         &n0,
//     );
//     let d = BigInt::mod_mul(
//         &BigInt::mod_pow(&rd, &n, &nn),
//         &((BigInt::one() + n * y.clone()) % nn),
//         &nn,
//     );
//     let capital_d = BigInt::mod_mul(
//         &BigInt::mod_pow(&g, &y, &n0),
//         &BigInt::mod_pow(&h, &beta, &n0),
//         &n0,
//     );

//     // generating hash e as non-interactive
//     let mut hasher = Sha256::new();
//     hasher.update(n.to_string().as_bytes());
//     hasher.update(q.to_string().as_bytes());
//     hasher.update(c.to_string().as_bytes());
//     hasher.update(capital_c.to_string().as_bytes());
//     hasher.update(d.to_string().as_bytes());
//     hasher.update(capital_d.to_string().as_bytes());
//     let result = hasher.finalize();
//     let modulus: BigInt = BigInt::from(2).pow(T);
//     let e = BigInt::from_bytes(&result) % modulus;

//     //prover's 2nd message
//     let z1 = y.clone() + (e.clone() * x.clone()); // integer
//     let z2 = BigInt::mod_mul(
//         &rd,
//         &BigInt::mod_pow(&r, &e.clone(), &n),
//         &n,
//     );
//     let z3 = beta.clone() + (alpha.clone() * e.clone()); // integer

//     ProofRPwR {capital_c, d, capital_d, z1, z2, z3}
// }

// pub fn zkp_range_proof_verifier(proof_rpwr: &ProofRPwR, n0: &BigInt, n: &BigInt, nn: &BigInt, q: &BigInt, h: &BigInt, g: &BigInt, c: &BigInt, ) -> bool {
//     // receiving proofs from prover
//     let ProofRPwR {capital_c, d, capital_d, z1, z2, z3,} = proof_rpwr;
    
//     // generating hash e as non-interactive
//     let mut hasher = Sha256::new();
//     hasher.update(n.to_string().as_bytes());
//     hasher.update(q.to_string().as_bytes());
//     hasher.update(c.to_string().as_bytes());
//     hasher.update(capital_c.to_string().as_bytes());
//     hasher.update(d.to_string().as_bytes());
//     hasher.update(capital_d.to_string().as_bytes());
//     let result = hasher.finalize();
//     let modulus: BigInt = BigInt::from(2).pow(T);
//     let e = BigInt::from_bytes(&result) % modulus;

//     // verifcation for range proof 1-3
//     let lhs1 = BigInt::mod_mul(
//         &BigInt::mod_pow(&proof_rpwr.z2, n, nn), // z2^n mod nn
//         &((BigInt::one() + n * proof_rpwr.z1.clone()) % nn), // (1+n)^z1 mod nn
//         nn,
//     );
//     let rhs1 = BigInt::mod_mul(
//         &proof_rpwr.d,
//         &BigInt::mod_pow(&c, &e, nn), 
//         nn
//     );

//     let lhs2 = BigInt::mod_mul(
//         &BigInt::mod_pow(&g, &proof_rpwr.z1, &n0), // g^z1 mod n0
//         &BigInt::mod_pow(&h, &proof_rpwr.z3, &n0), // h^z3 mod n0
//         &n0,
//     );
//     let rhs2 = BigInt::mod_mul(
//         &proof_rpwr.capital_d,
//         &BigInt::mod_pow(&proof_rpwr.capital_c, &e, &n0), // C^e mod n0
//         &n0,
//     );

//     let verif3 = // range cheek for z1
//     z1 >= &(BigInt::from(2).pow(T) * q) && 
//     z1 < &{BigInt::from(2).pow(T + L) * q};

//     println!("Verification_rpwr result: {}, {}, {}", lhs1==rhs1, lhs2 == rhs2, verif3);

//     lhs1 == rhs1 && lhs2 == rhs2 && verif3
// }

// // appendix c.3.4
// pub fn verifier_affran_setup() -> (BigInt, BigInt, BigInt, ProofQR, ProofQRdl) {
//     let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
//     let n0 = ek0.n.clone(); 

//     let x: BigInt = BigInt::sample_below(&n0);
//     let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);
//     let alpha: BigInt = BigInt::sample_below(&n0);
//     let g = BigInt::mod_pow(&h, &alpha, &n0);

//     // h, g -> proof needed
//     let proof_qr = zkp_qr_prover(&n0, &x, &h); // for h
//     let proof_qrdl = zkp_qrdl_prover(&n0, &h, &g, &alpha); // for g

//     (n0, h, g, proof_qr, proof_qrdl)
// }

// pub fn prover_verify_h_g(n0: &BigInt, h: &BigInt, g: &BigInt, proof_qr: &ProofQR, proof_qrdl: &ProofQRdl, ) -> bool {
//     // Prover verifies Verifiers h, g
//     let verif_qr = zkp_qr_verifier(&proof_qr, &n0, &h);
//     assert_eq!(verif_qr, true);
//     let verif_qrdl = zkp_qrdl_verifier(&proof_qrdl, &n0, &g, &h);
//     assert_eq!(verif_qrdl, true);

//     verif_qr && verif_qrdl
// }

// pub fn prover_affran_setup(n0: &BigInt, ) -> (BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, ) {
//     let (ek, dk) = Paillier::keypair_with_modulus_size(3072).keys();
//     let n = ek.n.clone();
//     let nn = n.clone() * n.clone();
//     let q = dk.q.clone();

//     // generating public c with x, r
//     let x = BigInt::sample_below(&n); // as a
//     let r = BigInt::sample_below(&n0);
//     let c = BigInt::mod_mul(
//         &BigInt::mod_pow(&r, &n, &nn),
//         &BigInt::mod_pow(&(BigInt::from(1) + n.clone()), &x, &nn),
//         &nn
//         );
//     // let proof_rpwr = zkp_range_proof_prover(n0, &n, &nn, &q, &h, &g, &x, &r, &c);
//     // -> c 에 대한 range proof 진행해야 하는가? 외부에서 들어오는 parameter 일 테니 아마도?

//     // generating public ca with a, alpha
//     let a = BigInt::sample_below(&n);
//     let alpha = BigInt::sample_below(&n);
//     let ca: BigInt = BigInt::mod_mul(
//         &(BigInt::mod_pow(&c, &a, &nn)),
//         &(BigInt::one() + n.clone() * alpha.clone()),
//         &nn
//     );

//     (n, nn, q, ca, c, a, alpha) // returning public parameters
// }

// pub fn zkp_affran_prover(
//     n0: &BigInt, 
//     n: &BigInt, 
//     nn: &BigInt, 
//     q: &BigInt, 
//     h: &BigInt, 
//     g: &BigInt, 
//     c: &BigInt, 
//     ca: &BigInt, 
//     a: &BigInt, //
//     alpha: &BigInt, //
// ) -> ProofAffRan {

//     // prover's 1st message
//     let k_big: BigInt = BigInt::from(2).pow(T+L+S) * q.pow(2);
//     let b = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * q.clone()));
//     let beta = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * k_big));
//     let rho1 = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n0));
//     let rho2 = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n0));
//     let rho3 = BigInt::sample_below(&(n0));
//     let rho4 = BigInt::sample_below(&(n0));

//     let capital_a = BigInt::mod_mul( // A = c^b * (1 + n*beta) mod nn
//         &(BigInt::mod_pow(&c, &b, &nn)),
//         &((BigInt::one() + n * beta.clone()) % nn),
//         &nn
//     );
//     let capital_b1 = BigInt::mod_mul( // B1 = g^b * h^rho1 mod n0
//         &(BigInt::mod_pow(&g, &b, &n0)),
//         &(BigInt::mod_pow(&h, &rho1, &n0)),
//         &n0
//     );
//     let capital_b2 = BigInt::mod_mul( // B2 = g^beta * h^rho2 mod n0
//         &(BigInt::mod_pow(&g, &beta, &n0)),
//         &(BigInt::mod_pow(&h, &rho2, &n0)),
//         &n0
//     );
//     let capital_b3 = BigInt::mod_mul( // B3 = g^a * h^rho3 mod n0
//         &(BigInt::mod_pow(&g, &a, &n0)),
//         &(BigInt::mod_pow(&h, &rho3, &n0)),
//         &n0
//     );
//     let capital_b4 = BigInt::mod_mul( // B4 = g^alpha * h^rho4 mod n0
//         &(BigInt::mod_pow(&g, &alpha, &n0)),
//         &(BigInt::mod_pow(&h, &rho4, &n0)),
//         &n0
//     );

//     // hashing e as non-interactive
//     let mut hasher = Sha256::new();
//     hasher.update(n.to_string().as_bytes());
//     hasher.update(q.to_string().as_bytes());
//     hasher.update(ca.to_string().as_bytes());
//     hasher.update(c.to_string().as_bytes());
//     hasher.update(capital_a.to_string().as_bytes());
//     hasher.update(capital_b1.to_string().as_bytes());
//     hasher.update(capital_b2.to_string().as_bytes());
//     hasher.update(capital_b3.to_string().as_bytes());
//     hasher.update(capital_b4.to_string().as_bytes());
//     let result = hasher.finalize();
//     let modulus = BigInt::from(2).pow(T);
//     let e = BigInt::from_bytes(&result) % modulus;

//     // prover's 2nd message
//     let z1 = b + e.clone() * a;
//     let z2 = beta + e.clone() * alpha;
//     let z3 = rho1 + e.clone() * rho3;
//     let z4 = rho2 + e.clone() * rho4;

//     ProofAffRan {capital_a, capital_b1, capital_b2, capital_b3, capital_b4, z1, z2, z3, z4}
// }

// pub fn zkp_affran_verifier(
//     proof_affran: &ProofAffRan, 
//     n0: &BigInt, 
//     n: &BigInt, 
//     nn: &BigInt, 
//     q: &BigInt, 
//     h: &BigInt, 
//     g: &BigInt, 
//     c: &BigInt, 
//     ca: &BigInt, 
// ) -> bool {

//     // getting proof for affran from prover
//     let big_k: BigInt = BigInt::from(2).pow(T+L+S) * q.pow(2);
//     let ProofAffRan {capital_a, capital_b1, capital_b2, capital_b3, capital_b4, z1, z2, z3, z4 } = proof_affran;
    
//     // hashing e as non-interactive    
//     let mut hasher = Sha256::new();
//     hasher.update(n.to_string().as_bytes());
//     hasher.update(q.to_string().as_bytes());
//     hasher.update(ca.to_string().as_bytes());
//     hasher.update(c.to_string().as_bytes());
//     hasher.update(capital_a.to_string().as_bytes());
//     hasher.update(capital_b1.to_string().as_bytes());
//     hasher.update(capital_b2.to_string().as_bytes());
//     hasher.update(capital_b3.to_string().as_bytes());
//     hasher.update(capital_b4.to_string().as_bytes());
//     let result = hasher.finalize();
//     let modulus: BigInt = BigInt::from(2).pow(T);
//     let e = BigInt::from_bytes(&result) % modulus;

//     // verifiers verification 1-5
//     let verif1 = // range check for z1
//     z1 >= &(BigInt::from(2).pow(T) * q) && 
//     z1 < &(BigInt::from(2).pow(T+L) * q);

//     let verif2 = // range check for z2
//     z2 >= &(BigInt::from(2).pow(T) * big_k.clone()) &&
//     z2 < &(BigInt::from(2).pow(T+L) * big_k.clone());

//     let lhs3 = BigInt::mod_mul(
//         &(BigInt::mod_pow(&c, &proof_affran.z1, &nn)),
//         &(BigInt::one() + n * proof_affran.z2.clone()), 
//         &nn
//     );
//     let rhs3 = BigInt::mod_mul(
//         &proof_affran.capital_a,
//         &(BigInt::mod_pow(&ca, &e, &nn)),
//         &nn,
//     );

//     let lhs4 = BigInt::mod_mul(
//         &(BigInt::mod_pow(&g, &proof_affran.z1, &n0)),
//         &(BigInt::mod_pow(&h, &proof_affran.z3, &n0)),
//         &n0
//     );
//     let rhs4 = BigInt::mod_mul(
//         &proof_affran.capital_b1,
//         &(BigInt::mod_pow(&proof_affran.capital_b3, &e, &n0)),
//         &n0
//     );

//     let lhs5 = BigInt::mod_mul(
//         &(BigInt::mod_pow(&g, &proof_affran.z2, &n0)),
//         &(BigInt::mod_pow(&h, &proof_affran.z4, &n0)),
//         &n0
//     );
//     let rhs5 = BigInt::mod_mul(
//         &proof_affran.capital_b2,
//         &(BigInt::mod_pow(&proof_affran.capital_b4, &e, &n0)),
//         &n0
//     );

//     println!("Verification_affran result: {}, {}, {}, {}, {}", verif1, verif2, lhs3 == rhs3, lhs4 == rhs4, lhs5 == rhs5);

//     verif1 && verif2 && lhs3 == rhs3 && lhs4 == rhs4 && lhs5 == rhs5
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_total_zkp_qr() {
//         let n0 = verifier_qr_setup();
//         let (x, h) = prover_qr_setup(&n0);
//         let proof_qr = zkp_qr_prover(&n0, &h, &x);
//         let verified_qr = zkp_qr_verifier(&proof_qr, &n0, &h);
//         assert!(verified_qr, "ZKPoKQR verification_qr failed!");
//     }

//     #[test]
//     fn test_total_zkp_qrdl() {
//         let n0 = verifier_qrdl_setup();
//         let (h, g, alpha) = prover_qrdl_setup(&n0);
//         let proof_qrdl = zkp_qrdl_prover(&n0, &h, &g, &alpha);
//         let verified_qrdl = zkp_qrdl_verifier(&proof_qrdl, &n0, &g, &h);
//         assert!(verified_qrdl, "ZKPoKQR verification_qrdl failed!");
//     }

//     #[test]
//     fn test_total_zkp_range_proof() {
//         let (n0, h, g) = verifier_rp_setup();
//         let (n, nn, q, c, x, r) = prover_rp_setup();
//         let proof_rpwr = zkp_range_proof_prover(&n0, &n, &nn, &q, &h, &g, &x, &r, &c);
//         let verified_range_proof = zkp_range_proof_verifier(&proof_rpwr, &n0, &n, &nn, &q, &h, &g, &c);
//         assert!(verified_range_proof, "Range Proof for x failed!"); // verify for x in special q
//     }

//     #[test]
//     fn test_total_zkp_affran() {
//         let (n0, h, g, proof_qr, proof_qrdl) = verifier_affran_setup();
//         assert_eq!(prover_verify_h_g(&n0, &h, &g, &proof_qr, &proof_qrdl), true);
//         let (n, nn, q, ca, c, a, alpha) = prover_affran_setup(&n0);
//         let proof_affran = zkp_affran_prover(&n0, &n, &nn, &q, &h, &g, &c, &ca, &a, &alpha);
//         let verified_affran = zkp_affran_verifier(&proof_affran, &n0, &n, &nn, &q, &h, &g, &c, &ca);
//         assert!(verified_affran, "Paillier encryption with range proof failed!");
//     }
// }