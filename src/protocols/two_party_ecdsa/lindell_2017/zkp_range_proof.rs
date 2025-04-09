use curv::BigInt;
use curv::arithmetic::One;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{BasicOps, Modulo, Converter};

use sha2::{Sha256, Digest};

use paillier::{KeyGeneration, Paillier};

pub const T: u32 = 128;
pub const L: u32 = 80;

pub struct ProofRPwR {
    capital_c: BigInt,
    d: BigInt,
    capital_d: BigInt,
    z1: BigInt,
    z2: BigInt,
    z3: BigInt,
}

pub fn verifier_setup() -> (BigInt, BigInt, BigInt) {
    let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
    let n0 = ek0.n.clone();

    // for Pedersen commitment parameter h, g
    let x = BigInt::sample_below(&n0);
    let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);
    let alpha = BigInt::sample_below(&n0);
    let g = BigInt::mod_pow(&h, &alpha, &n0);

    (n0, h, g)
}

pub fn prover_setup() -> (BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, ) {
    let (ek, dk) = Paillier::keypair_with_modulus_size(3072).keys();
    let n = ek.n.clone();
    let nn = n.clone() * n.clone();
    let q = dk.q.clone();

    let x = BigInt::sample_below(&n); // secret witness / message a, b
    let r = BigInt::sample_below(&n); // secret witness / randomness
    let c = BigInt::mod_mul(
        &BigInt::mod_pow(&r, &n, &nn),
        &BigInt::mod_pow(&(BigInt::from(1) + n.clone()), &x, &nn),
        &nn
    );

    (n, nn, q, c, x, r)
}

pub fn zkp_range_proof_prover(
    n0: &BigInt, 
    n: &BigInt, 
    nn: &BigInt, 
    q: &BigInt, 
    h: &BigInt, 
    g: &BigInt, 
    x: &BigInt, 
    r: &BigInt, 
    c: &BigInt, 
) -> ProofRPwR {
    
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
    let d = BigInt::mod_mul(
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

    //prover's 2nd message
    let z1 = y.clone() + (e.clone() * x.clone()); // integer
    let z2 = BigInt::mod_mul(
        &rd,
        &BigInt::mod_pow(&r, &e.clone(), &n),
        &n,
    );
    let z3 = beta.clone() + (alpha.clone() * e.clone()); // integer

    ProofRPwR {capital_c, d, capital_d, z1, z2, z3}
}

pub fn zkp_range_proof_verifier(
    proof_rpwr: &ProofRPwR, 
    n0: &BigInt, 
    n: &BigInt, 
    nn: &BigInt, 
    q: &BigInt, 
    h: &BigInt, 
    g: &BigInt, 
    c: &BigInt, 
) -> bool {
    // receiving proofs from prover
    let ProofRPwR {capital_c, d, capital_d, z1, z2, z3,} = proof_rpwr;
    
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
        &BigInt::mod_pow(&proof_rpwr.z2, n, nn), // z2^n mod nn
        &((BigInt::one() + n * proof_rpwr.z1.clone()) % nn), // (1+n)^z1 mod nn
        nn,
    );
    let rhs1 = BigInt::mod_mul(
        &proof_rpwr.d,
        &BigInt::mod_pow(&c, &e, nn), 
        nn
    );
    // verifcation 2
    let lhs2 = BigInt::mod_mul(
        &BigInt::mod_pow(&g, &proof_rpwr.z1, &n0), // g^z1 mod n0
        &BigInt::mod_pow(&h, &proof_rpwr.z3, &n0), // h^z3 mod n0
        &n0,
    );
    let rhs2 = BigInt::mod_mul(
        &proof_rpwr.capital_d,
        &BigInt::mod_pow(&proof_rpwr.capital_c, &e, &n0), // C^e mod n0
        &n0,
    );
    // verifcation 3
    let verif3 = // range cheek for z1
    z1 >= &(BigInt::from(2).pow(T) * q) && 
    z1 < &{BigInt::from(2).pow(T + L) * q};

    println!("Verification_rpwr result: {}, {}, {}", lhs1==rhs1, lhs2 == rhs2, verif3);

    lhs1 == rhs1 && lhs2 == rhs2 && verif3
}

#[test]
pub fn test_zkp_range_proof() {
    let (n0, h, g) = verifier_setup();
    let (n, nn, q, c, x, r) = prover_setup();
    let proof_rpwr = zkp_range_proof_prover(&n0, &n, &nn, &q, &h, &g, &x, &r, &c);
    let verified_range_proof = zkp_range_proof_verifier(&proof_rpwr, &n0, &n, &nn, &q, &h, &g, &c);
    assert!(verified_range_proof, "Paillier encryption with range proof failed!")
}