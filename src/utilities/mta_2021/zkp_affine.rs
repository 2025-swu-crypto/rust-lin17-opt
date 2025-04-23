use curv::BigInt;
use curv::arithmetic::One;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{BasicOps, Modulo, Converter};
use sha2::{Sha256, Digest};
// use paillier::{KeyGeneration, Paillier};
use crate::utilities::mta_2021::zkp_p::*;
use crate::utilities::mta_2021::zkp_qr::*;
use crate::utilities::mta_2021::zkp_qrdl::*;

pub const S: u32 = 128;
pub const T: u32 = 128;
pub const L: u32 = 80;

pub struct AffineProof {
    capital_a: BigInt,
    capital_b1: BigInt,
    capital_b2: BigInt,
    capital_b3: BigInt,
    capital_b4: BigInt,
    z1: BigInt,
    z2: BigInt,
    z3: BigInt,
    z4: BigInt,
}

// Proof of Paillier-Pedersen Range_bounded Affine Operation
// proof for "a" and "alpha"
pub fn affine_verifier_setup() -> (BigInt, BigInt, BigInt, QRProof, QRdlProof) {
    let keypair = PiPProver::generate_paillier_blum_primes(3072);
    let n0 = keypair.n.clone();
    // let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
    // let n0 = ek0.n.clone(); 

    let x: BigInt = BigInt::sample_below(&n0);
    let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);
    let alpha: BigInt = BigInt::sample_below(&n0);
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

pub fn affine_prover_setup() -> (BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, ) {
    let keypair = PiPProver::generate_paillier_blum_primes(3072);
    let n = keypair.n.clone();
    let nn = n.clone() * n.clone();
    let q = keypair.get_q().clone();
    // let (ek, dk) = Paillier::keypair_with_modulus_size(3072).keys();
    // let n = ek.n.clone();
    // let nn = n.clone() * n.clone();
    // let q = dk.q.clone();

    // generating public c with x, r
    let x = BigInt::sample_below(&q); // as a
    let r = BigInt::sample_below(&n);
    let c = BigInt::mod_mul(
        &BigInt::mod_pow(&r, &n, &nn),
        &BigInt::mod_pow(&(BigInt::from(1) + n.clone()), &x, &nn),
        &nn
        );
    // let proof_rpwr = zkp_range_proof_prover(n0, &n, &nn, &q, &h, &g, &x, &r, &c);
    // -> c 에 대한 range proof 진행해야 하는가? 외부에서 들어오는 parameter 일 테니 아마도// -

    // generating public ca with a, alpha
    let a = BigInt::sample_below(&q); // n
    let alpha = BigInt::sample_below(&n);
    let ca: BigInt = BigInt::mod_mul(
        &(BigInt::mod_pow(&c, &a, &nn)),
        &(BigInt::one() + n.clone() * alpha.clone()),
        &nn
    );

    (n, nn, q, ca, c, a, alpha) // returning public parameters
}

// Paillier Encryption witn range proof for "a and alpha"
pub fn generate_zkp_affine(
    n0: &BigInt, 
    n: &BigInt, 
    nn: &BigInt, 
    q: &BigInt, 
    h: &BigInt, 
    g: &BigInt, 
    c: &BigInt, 
    ca: &BigInt, 
    a: &BigInt, //
    alpha: &BigInt, //
) -> AffineProof {

    // prover's 1st message
    let k_big: BigInt = BigInt::from(2).pow(T+L+S) * q.pow(2);
    let b = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * q.clone()));
    let beta = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * k_big));
    let rho1 = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n0));
    let rho2 = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n0));
    let rho3 = BigInt::sample_below(&(n0));
    let rho4 = BigInt::sample_below(&(n0));

    let capital_a = BigInt::mod_mul( // A = c^b * (1 + n*beta) mod nn
        &(BigInt::mod_pow(&c, &b, &nn)),
        &((BigInt::one() + n * beta.clone()) % nn),
        &nn
    );
    let capital_b1 = BigInt::mod_mul( // B1 = g^b * h^rho1 mod n0
        &(BigInt::mod_pow(&g, &b, &n0)),
        &(BigInt::mod_pow(&h, &rho1, &n0)),
        &n0
    );
    let capital_b2 = BigInt::mod_mul( // B2 = g^beta * h^rho2 mod n0
        &(BigInt::mod_pow(&g, &beta, &n0)),
        &(BigInt::mod_pow(&h, &rho2, &n0)),
        &n0
    );
    let capital_b3 = BigInt::mod_mul( // B3 = g^a * h^rho3 mod n0
        &(BigInt::mod_pow(&g, &a, &n0)),
        &(BigInt::mod_pow(&h, &rho3, &n0)),
        &n0
    );
    let capital_b4 = BigInt::mod_mul( // B4 = g^alpha * h^rho4 mod n0
        &(BigInt::mod_pow(&g, &alpha, &n0)),
        &(BigInt::mod_pow(&h, &rho4, &n0)),
        &n0
    );

    // hashing e as non-interactive / e in 2^T
    let mut hasher = Sha256::new();
    hasher.update(n.to_string().as_bytes());
    hasher.update(q.to_string().as_bytes());
    hasher.update(ca.to_string().as_bytes());
    hasher.update(c.to_string().as_bytes());
    hasher.update(capital_a.to_string().as_bytes());
    hasher.update(capital_b1.to_string().as_bytes());
    hasher.update(capital_b2.to_string().as_bytes());
    hasher.update(capital_b3.to_string().as_bytes());
    hasher.update(capital_b4.to_string().as_bytes());
    let result = hasher.finalize();
    let modulus = BigInt::from(2).pow(T);
    let e = BigInt::from_bytes(&result) % modulus;

    // prover's 2nd message
    let z1 = b.clone() + e.clone() * a.clone();
    let z2 = beta.clone() + e.clone() * alpha.clone();
    let z3 = rho1.clone() + e.clone() * rho3.clone();
    let z4 = rho2.clone() + e.clone() * rho4.clone();

    AffineProof {capital_a, capital_b1, capital_b2, capital_b3, capital_b4, z1, z2, z3, z4}
}

pub fn verify_zkp_affine(
    zkp_affine: &AffineProof, 
    n0: &BigInt, 
    n: &BigInt, 
    nn: &BigInt, 
    q: &BigInt, 
    h: &BigInt, 
    g: &BigInt, 
    c: &BigInt, 
    ca: &BigInt, 
) -> bool {

    // getting proof for affran from prover
    let big_k: BigInt = BigInt::from(2).pow(T+L+S) * q.pow(2);
    let &AffineProof { ref capital_a, ref capital_b1, ref capital_b2, ref capital_b3, ref capital_b4, ref z1, ref z2, ref z3, ref z4 } = zkp_affine;
    
    // hashing e as non-interactive    
    let mut hasher = Sha256::new();
    hasher.update(n.to_string().as_bytes());
    hasher.update(q.to_string().as_bytes());
    hasher.update(ca.to_string().as_bytes());
    hasher.update(c.to_string().as_bytes());
    hasher.update(capital_a.to_string().as_bytes());
    hasher.update(capital_b1.to_string().as_bytes());
    hasher.update(capital_b2.to_string().as_bytes());
    hasher.update(capital_b3.to_string().as_bytes());
    hasher.update(capital_b4.to_string().as_bytes());
    let result = hasher.finalize();
    let modulus: BigInt = BigInt::from(2).pow(T);
    let e = BigInt::from_bytes(&result) % modulus;

    // verifiers verification 1-5
    let verif1 = // range check for z1
    z1 >= &(BigInt::from(2).pow(T) * q) && 
    z1 < &(BigInt::from(2).pow(T+L) * q);

    let verif2 = // range check for z2
    z2 >= &(BigInt::from(2).pow(T) * big_k.clone()) &&
    z2 < &(BigInt::from(2).pow(T+L) * big_k.clone());

    let lhs3 = BigInt::mod_mul(
        &(BigInt::mod_pow(&c, &z1, &nn)),
        &(BigInt::one() + n * z2.clone()), 
        &nn
    );
    let rhs3 = BigInt::mod_mul(
        &capital_a,
        &(BigInt::mod_pow(&ca, &e, &nn)),
        &nn,
    );

    let lhs4 = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &z1, &n0)),
        &(BigInt::mod_pow(&h, &z3, &n0)),
        &n0
    );
    let rhs4 = BigInt::mod_mul(
        &capital_b1,
        &(BigInt::mod_pow(&capital_b3, &e, &n0)),
        &n0
    );

    let lhs5 = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &z2, &n0)),
        &(BigInt::mod_pow(&h, &z4, &n0)),
        &n0
    );
    let rhs5 = BigInt::mod_mul(
        &capital_b2,
        &(BigInt::mod_pow(&capital_b4, &e, &n0)),
        &n0
    );

    println!("Verification_affran result: {}, {}, {}, {}, {}", verif1, verif2, lhs3 == rhs3, lhs4 == rhs4, lhs5 == rhs5);

    verif1 && verif2 && lhs3 == rhs3 && lhs4 == rhs4 && lhs5 == rhs5
}

#[test]
pub fn test_zkp_affran() {
    let (n0, h, g, zkp_qr, zkp_qrdl) = affine_verifier_setup();
    assert_eq!(prover_verify_h_g(&n0, &h, &g, &zkp_qr, &zkp_qrdl), true);
    let (n, nn, q, ca, c, a, alpha) = affine_prover_setup(); // c분리.
    let zkp_affine = generate_zkp_affine(&n0, &n, &nn, &q, &h, &g, &c, &ca, &a, &alpha);
    let verif_affran = verify_zkp_affine(&zkp_affine, &n0, &n, &nn, &q, &h, &g, &c, &ca);
    assert!(verif_affran, "Paillier encryption with affine range proof failed!");
}