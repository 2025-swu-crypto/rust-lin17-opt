
// zkpok_qr.rs - Appendix C.3.1: Proof of Knowledge of h ∈ QR_n0

use curv::arithmetic::traits::*;
use curv::BigInt;
use curv::arithmetic::Modulo;
use sha2::{Digest, Sha256};
use paillier::KeyGeneration;

#[derive(Clone, Debug)]
pub struct ProverQR {
    pub n0: BigInt,
    pub x: BigInt,
    pub r: BigInt,
}

#[derive(Clone, Debug)]
pub struct ProofQR {
    pub a: BigInt,
    pub z: BigInt,
    pub h: BigInt,
}

impl ProverQR {
    pub fn generate_init() -> ProverQR {
        let (ek, dk) = paillier::Paillier::keypair_safe_primes_with_modulus_size(3072).keys();
        let n0 = ek.n.clone();
        let x = BigInt::sample_below(&(dk.q.clone() / BigInt::from(3)));
        let r = BigInt::sample_below(&n0);

        ProverQR { n0, x, r }
    }

    pub fn prove(&self) -> (ProofQR, BigInt) {
        let n0 = &self.n0;
        let x = &self.x;
        let r = &self.r;

        let a = BigInt::mod_pow(r, &BigInt::from(2), n0);
        let h = BigInt::mod_pow(x, &BigInt::from(2), n0);

        let mut hasher = Sha256::default();

        hasher.update(&a.to_string().as_bytes());
        hasher.update(&h.to_string().as_bytes());
        
        let result_a_h = hasher.finalize();
        let last_byte = result_a_h[result_a_h.len() - 1];

        let e = if last_byte & 1 == 1{
            BigInt::from(1)
        } else {
            BigInt::from(0)
        };

        let z = (BigInt::mod_pow(x, &e, n0) * r) % n0;

        (
            ProofQR {
                a,
                z,
                h,
            },
            e,
        )
    }
}

pub fn verify(n0: &BigInt, proof: &ProofQR, e: &BigInt) -> bool {
    let ProofQR { a, z, h } = proof;

    let lhs = BigInt::mod_pow(z, &BigInt::from(2), n0);
    let rhs = (BigInt::mod_pow(h, e, n0) * a) % n0;

    println!("Verification_qr result: {}", lhs==rhs);
    
    lhs == rhs
}

#[test]
pub fn test_qr() {
    let prover = ProverQR::generate_init();
    let (proof, challenge) = prover.prove();
    assert!(verify(&prover.n0, &proof, &challenge));
}