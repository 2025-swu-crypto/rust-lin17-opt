
use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::{Paillier, KeyGeneration};

/// ZKPoK for QR-DL (Appendix C.3.2)

pub struct ProverQRDL {
    pub n0: BigInt,
    pub h: BigInt,
    pub g: BigInt,
    pub a: BigInt,
    pub alpha: BigInt,
    pub beta: BigInt,
}

pub struct ProofQRDL {
    pub a: BigInt,
    pub z: BigInt,
}

impl ProverQRDL {
    pub fn generate_init() -> ProverQRDL {
        let (ek, _) = Paillier::keypair_safe_primes_with_modulus_size(3072).keys();
        let n0 = ek.n.clone();

        // h ∈ QR_n0
        let h = BigInt::mod_pow(&BigInt::sample_below(&n0)/* x */, &BigInt::from(2), &n0);

        // alpha ∈ [0, n0)
        let alpha = BigInt::sample_below(&n0);

        // g = h^alpha mod n0
        let g = BigInt::mod_pow(&h, &alpha, &n0);

        // beta ∈ [1, 2^s * n0]
        let s: u32 = 128;
        let beta = BigInt::sample_range(&BigInt::one(), &(BigInt::from(2).pow(s) * &n0));

        // a = h^beta mod n0
        let a = BigInt::mod_pow(&h, &beta, &n0);

        ProverQRDL {
            n0,
            h,
            g,
            a,
            alpha,
            beta,
        }
    }

    pub fn prove(&self, e: &BigInt) -> ProofQRDL {
        let z = e * &self.alpha + &self.beta;
        ProofQRDL {
            a: self.a.clone(),
            z,
        }
    }
}

pub fn verify(n0: &BigInt, h: &BigInt, g: &BigInt, proof: &ProofQRDL, e: &BigInt) -> bool {
    let lhs = BigInt::mod_pow(h, &proof.z, n0);
    let rhs = (BigInt::mod_pow(g, e, n0) * &proof.a) % n0;

    println!("Verification_qrdl result: {}", lhs == rhs);
    lhs == rhs
}

#[test]
pub fn test_qrdl() {
    let prover = ProverQRDL::generate_init();
    let e = BigInt::sample(128);
    let proof = prover.prove(&e);
    assert!(verify(&prover.n0, &prover.h, &prover.g, &proof, &e));
}