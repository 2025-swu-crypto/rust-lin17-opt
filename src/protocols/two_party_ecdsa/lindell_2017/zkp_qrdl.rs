use curv::BigInt;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{BasicOps, Modulo};
use sha2::{Sha256, Digest};
use paillier::{KeyGeneration, Paillier};

pub const S: u32 = 128;

pub struct ProofQRdl {
    a: BigInt,
    z: BigInt,
}

// input n0, h, g, alpha, proof_qrdl, 

pub fn verifier_setup() -> BigInt {
    let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
    let n0 = ek0.n.clone();

    n0
}

pub fn prover_setup(n0: &BigInt, ) -> (BigInt, BigInt, BigInt) {    
    let x = BigInt::sample_below(&n0);
    let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);

    let alpha = BigInt::sample_below(&n0);
    let g = BigInt::mod_pow(&h, &alpha, &n0);

    (h, g, alpha)
}

pub fn zkp_qrdl_prover(n0: &BigInt, h: &BigInt, g: &BigInt, alpha: &BigInt, ) -> ProofQRdl {
    let beta = BigInt::sample_range(&BigInt::from(1), &(BigInt::from(2).pow(S-1) * n0)) * 2;
    let a = BigInt::mod_pow(&h, &beta, &n0); // h^beta

    let mut hasher = Sha256::new();
    hasher.update(a.to_string().as_bytes());
    hasher.update(g.to_string().as_bytes());
    let result = hasher.finalize();
    let last_byte = result[result.len() - 1];
    let e = if last_byte & 1 ==1{ // e
        BigInt::from(1)
    } else {
        BigInt::from(0)
    };

    let z = e.clone() * alpha + beta; // e * alpha + beta (integer)

    ProofQRdl {a, z}
}

pub fn zkp_qrdl_verifier(proof_qrdl: &ProofQRdl, n0: &BigInt, h: &BigInt, g: &BigInt, ) -> bool {
    let ProofQRdl {a, z} = proof_qrdl;

    let mut hasher = Sha256::new();
    hasher.update(a.to_string().as_bytes());
    hasher.update(g.to_string().as_bytes());
    let result = hasher.finalize();
    let last_byte = result[result.len() - 1];
    let e = if last_byte & 1 ==1{ // e
        BigInt::from(1)
    } else {
        BigInt::from(0)
    };

    let lhs = BigInt::mod_pow(&h, &proof_qrdl.z, &n0);
    let rhs = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &e, &n0)),
        &proof_qrdl.a,
        &n0,
    );

    println!("Verification_qrdl result: {}", lhs == rhs);

    lhs == rhs
}

#[test]
pub fn test_zkp_qrdl() {
    let n0 = verifier_setup();
    let (h, g, alpha) = prover_setup(&n0);
    let proof_qrdl = zkp_qrdl_prover(&n0, &h, &g, &alpha);
    let verified_qrdl = zkp_qrdl_verifier(&proof_qrdl, &n0, &h, &g);
    assert!(verified_qrdl, "ZKPoKQRdl verification failed!")
}