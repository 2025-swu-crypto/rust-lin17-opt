use curv::BigInt;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::Modulo;
use sha2::{Sha256, Digest};
use paillier::{KeyGeneration, Paillier};

pub struct ProofQR {
    a: BigInt,
    z: BigInt,
}

// input n0, x, h

pub fn verifier_setup() -> BigInt {
    let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
    let n0 = ek0.n.clone();

    n0
}

pub fn prover_setup(n0: &BigInt, )  -> (BigInt, BigInt) {
    let x: BigInt = BigInt::sample_below(&n0);
    let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);

    (x, h)
}

pub fn zkp_qr_prover(n0: &BigInt, h: &BigInt, x: &BigInt, ) -> ProofQR {
    let r: BigInt = BigInt::sample_below(&n0);
    let a = BigInt::mod_pow(&r, &BigInt::from(2), n0);

    let mut hasher = Sha256::default();
    hasher.update(&a.to_string().as_bytes());
    hasher.update(&h.to_string().as_bytes()); 
    let result = hasher.finalize();
    let last_byte = result[result.len() - 1];
    let e = if last_byte & 1 == 1{
        BigInt::from(1)
    } else {
        BigInt::from(0)
    };

    let z = BigInt::mod_mul(
        &(BigInt::mod_pow(&x, &e, n0)), 
        &r, 
        &n0
    );

    ProofQR {a, z}
}

pub fn zkp_qr_verifier(proof_qr: &ProofQR, n0: &BigInt, h:&BigInt, ) -> bool {
    let ProofQR {a, z} = proof_qr; // a, z

    let mut hasher = Sha256::default();
    hasher.update(&proof_qr.a.to_string().as_bytes());
    hasher.update(&h.to_string().as_bytes()); 
    let result = hasher.finalize();
    let last_byte = result[result.len() - 1];
    let e = if last_byte & 1 == 1{
        BigInt::from(1)
    } else {
        BigInt::from(0)
    }; //e

    let lhs = BigInt::mod_pow(&proof_qr.z, &BigInt::from(2), &n0); // z^2
    let rhs = BigInt::mod_mul( // h^e * a 
        &(BigInt::mod_pow(&h, &e, &n0)),
        &proof_qr.a,
        &n0,
    );

    println!("Verification_qr result: {}", lhs == rhs);

    lhs == rhs

}

#[test]
pub fn test_zkp_qr() {
    let n0 = verifier_setup();
    let (x, h) = prover_setup(&n0);
    let proof_qr = zkp_qr_prover(&n0, &h, &x);
    let verified_qr = zkp_qr_verifier(&proof_qr, &n0, &h);
    assert!(verified_qr, "ZKPoKQR verification failed!")
}