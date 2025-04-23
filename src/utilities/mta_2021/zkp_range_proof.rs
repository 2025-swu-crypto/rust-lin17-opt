use curv::BigInt;
use curv::arithmetic::One;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{BasicOps, Modulo, Converter};
use sha2::{Sha256, Digest};
// use paillier::{KeyGeneration, Paillier};
use crate::utilities::mta_2021::zkp_p::*;
use crate::utilities::mta_2021::zkp_qr::*;
use crate::utilities::mta_2021::zkp_qrdl::*;

pub const T: u32 = 128;
pub const L: u32 = 80;

#[derive(Debug)]
pub struct RPwRProof {
    capital_c: BigInt,
    d: BigInt,
    capital_d: BigInt,
    z1: BigInt,
    z2: BigInt,
    z3: BigInt,
}

// ZKPoK for Paillier Encryption with Range Proof under Strong-RSA Assumption
// proof for "x"

pub fn range_proof_verifier_setup() -> (BigInt, BigInt, BigInt, QRProof, QRdlProof) {
    let keypair = PiPProver::generate_paillier_blum_primes(3072);
    let n0 = keypair.n.clone();
    // let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
    // let n0 = ek0.n.clone();

    // for Pedersen commitment parameter h, g
    let x = BigInt::sample_below(&n0);
    let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);
    let alpha = BigInt::sample_below(&n0);
    let g = BigInt::mod_pow(&h, &alpha, &n0);

    // h, g -> proof needed
    let zkp_qr = generate_zkp_qr(&n0, &x, &h); // for h
    let zkp_qrdl = generate_zkp_qrdl(&n0, &h, &g, &alpha); // for g

    (n0, h, g, zkp_qr, zkp_qrdl)
}

pub fn prover_verify_h_g(n0: &BigInt, h: &BigInt, g: &BigInt, zkp_qr: &QRProof, zkp_qrdl: &QRdlProof, ) -> bool {
    // Prover verifies Verifiers h, g
    let verif_qr = verify_zkp_qr(&zkp_qr, &n0, &h);
    assert_eq!(verif_qr, true);
    let verif_qrdl = verify_zkp_qrdl(&zkp_qrdl, &n0, &h, &g);
    assert_eq!(verif_qrdl, true);

    verif_qr && verif_qrdl
}

pub fn range_proof_prover_setup() -> (BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, ) {
    let keypair = PiPProver::generate_paillier_blum_primes(3072);
    let n = keypair.n.clone();
    let nn = n.clone() * n.clone();
    let q = keypair.get_q().clone();
    // let (ek, dk) = Paillier::keypair_with_modulus_size(3072).keys();
    // let n = ek.n.clone();
    // let nn = n.clone() * n.clone();
    // let q = dk.q.clone();

    let x = BigInt::sample_below(&q); // secret witness / like message a, b
    let r = BigInt::sample_below(&n); // secret witness / randomness
    let c = BigInt::mod_mul( // enc of x with r
        &BigInt::mod_pow(&r, &n, &nn),
        &BigInt::mod_pow(&(BigInt::from(1) + n.clone()), &x, &nn),
        &nn
    );

    (n, nn, q, c, x, r)
}

pub fn generate_zkp_range_proof(
    n0: &BigInt, 
    n: &BigInt, 
    nn: &BigInt, 
    q: &BigInt, 
    h: &BigInt, 
    g: &BigInt, 
    x: &BigInt, 
    r: &BigInt, 
    c: &BigInt, 
) -> RPwRProof {
    
    // prover's 1st message
    let alpha = BigInt::sample_below(&n0);
    let beta = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n0));
    let y = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * q));
    let rd = BigInt::sample_below(&n);

    // Pedersen commitment of "x" with randomness "alpha" mod n0
    let capital_c = BigInt::mod_mul( // C = g^x * h^alpha mod n0
        &BigInt::mod_pow(&g, &x, &n0),
        &BigInt::mod_pow(&h, &alpha, &n0),
        &n0,
    );

    let d = BigInt::mod_mul( // d = rd^n * (1 + ny) mod nn
        &BigInt::mod_pow(&rd, &n, &nn),
        &((BigInt::one() + n * y.clone()) % nn), // (1 + ny) mod nn
        &nn,
    );
    
    // Pedersen commitment of "y" with randomness "beta" mod n0
    let capital_d = BigInt::mod_mul( // D = g^y * h^beta mod n0
        &BigInt::mod_pow(&g, &y, &n0),
        &BigInt::mod_pow(&h, &beta, &n0), 
        &n0,
    );

    // hashing e as non-interactive / e in 2^T
    let mut hasher = Sha256::new();
    hasher.update(n.to_string().as_bytes());
    hasher.update(q.to_string().as_bytes());
    hasher.update(c.to_string().as_bytes());
    hasher.update(capital_c.to_string().as_bytes());
    hasher.update(d.to_string().as_bytes());
    hasher.update(capital_d.to_string().as_bytes());
    let result = hasher.finalize();
    let modulus: BigInt = BigInt::from(2).pow(T);
    let e = BigInt::from_bytes(&result) % modulus;

    //prover's 2nd message
    let z1 = y.clone() + (e.clone() * x.clone()); // integer
    let z2 = BigInt::mod_mul(
        &rd,
        &BigInt::mod_pow(&r, &e.clone(), &n),
        &n,
    );
    let z3 = beta.clone() + (alpha.clone() * e.clone()); // integer

    RPwRProof {capital_c, d, capital_d, z1, z2, z3}
}

pub fn verify_zkp_range_proof(
    zkp_rpwr: &RPwRProof, 
    n0: &BigInt, 
    n: &BigInt, 
    nn: &BigInt, 
    q: &BigInt, 
    h: &BigInt, 
    g: &BigInt, 
    c: &BigInt, 
) -> bool {
    // receiving proofs from prover
    // let ProofRPwR {capital_c, d, capital_d, z1, z2, z3,} = proof_rpwr;
    let &RPwRProof { ref capital_c, ref d, ref capital_d, ref z1, ref z2, ref z3 } = zkp_rpwr;

    // generating hash e as non-interactive
    let mut hasher = Sha256::new();
    hasher.update(n.to_string().as_bytes());
    hasher.update(q.to_string().as_bytes());
    hasher.update(c.to_string().as_bytes());
    hasher.update(capital_c.to_string().as_bytes());
    hasher.update(d.to_string().as_bytes());
    hasher.update(capital_d.to_string().as_bytes());
    let result = hasher.finalize();
    let modulus: BigInt = BigInt::from(2).pow(T);
    let e = BigInt::from_bytes(&result) % modulus;

    // verifcation 1
    let lhs1 = BigInt::mod_mul(
        &BigInt::mod_pow(&z2, n, nn), // z2^n mod nn
        &((BigInt::one() + n * z1.clone()) % nn), // (1+n)^z1 mod nn
        nn,
    );
    let rhs1 = BigInt::mod_mul(
        &d,
        &BigInt::mod_pow(&c, &e, nn), 
        nn
    );
    // verifcation 2
    let lhs2 = BigInt::mod_mul(
        &BigInt::mod_pow(&g, &z1, &n0), // g^z1 mod n0
        &BigInt::mod_pow(&h, &z3, &n0), // h^z3 mod n0
        &n0,
    );
    let rhs2 = BigInt::mod_mul(
        &capital_d,
        &BigInt::mod_pow(&capital_c, &e, &n0), // C^e mod n0
        &n0,
    );
    // verifcation 3
    let verif3 = // range cheek for z1
    z1 >= &(BigInt::from(2).pow(T) * q) && 
    z1 < &{BigInt::from(2).pow(T + L) * q};

    println!("Verification_rpwr result: {}, {}, {}", lhs1==rhs1, lhs2 == rhs2, verif3);
    // println!("1: {}, \n2: {}, \n3: {}, \n4: {}, \n5: {}, \n6: {}", capital_c, d, capital_d, z1, z2, z3);
    lhs1 == rhs1 && lhs2 == rhs2 && verif3
}

#[test]
pub fn test_zkp_range_proof() {
    let (n0, h, g, zkp_qr, zkp_qrdl) = range_proof_verifier_setup();
    assert_eq!(prover_verify_h_g(&n0, &h, &g, &zkp_qr, &zkp_qrdl), true);
    let (n, nn, q, c, x, r) = range_proof_prover_setup();
    let zkp_rpwr = generate_zkp_range_proof(&n0, &n, &nn, &q, &h, &g, &x, &r, &c);
    // println!("test proof_rpwr: {:?}", proof_rpwr);
    let verif_range_proof = verify_zkp_range_proof(&zkp_rpwr, &n0, &n, &nn, &q, &h, &g, &c);
    assert!(verif_range_proof, "Paillier encryption with range proof failed!")
}