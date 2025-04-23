use curv::BigInt;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{BasicOps, Modulo};
use sha2::{Sha256, Digest};
// use paillier::{KeyGeneration, Paillier};
use crate::utilities::mta_2021::zkp_p::PiPProver;

pub const S: u32 = 128;

pub struct QRdlProof {
    pub a: BigInt,
    pub z: BigInt,
}

// Quadratic Residue discrete log proof
// input n0, h, g, alpha, zkp_qrdl, 

pub fn qrdl_verifier_setup() -> BigInt {
    let keypair = PiPProver::generate_paillier_blum_primes(3072);
    let n0 = keypair.n.clone();
    // let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
    // let n0 = ek0.n.clone();

    n0
}

pub fn qrdl_prover_setup(n0: &BigInt, ) -> (BigInt, BigInt, BigInt, ) {    
    let x = BigInt::sample_below(&n0);
    let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);

    let alpha = BigInt::sample_below(&n0);
    let g = BigInt::mod_pow(&h, &alpha, &n0);

    (h, g, alpha)
}

pub fn generate_zkp_qrdl(n0: &BigInt, h: &BigInt, g: &BigInt, alpha: &BigInt, ) -> QRdlProof {
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

    QRdlProof {a, z}
}

pub fn verify_zkp_qrdl(zkp_qrdl: &QRdlProof, n0: &BigInt, h: &BigInt, g: &BigInt, ) -> bool {
    // let QRdlProof {a, z} = zkp_qrdl;
    let &QRdlProof {ref a, ref z} = zkp_qrdl;

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

    let lhs = BigInt::mod_pow(&h, &z, &n0);
    let rhs = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &e, &n0)),
        &a,
        &n0,
    );

    println!("Verification_qrdl result: {}", lhs == rhs);

    lhs == rhs
}

#[test]
pub fn test_zkp_qrdl() {
    let n0 = qrdl_verifier_setup();
    let (h, g, alpha) = qrdl_prover_setup(&n0);
    let zkp_qrdl = generate_zkp_qrdl(&n0, &h, &g, &alpha);
    let verified_qrdl = verify_zkp_qrdl(&zkp_qrdl, &n0, &h, &g);
    assert!(verified_qrdl, "ZKPoKQRdl verification failed!")
}