use curv::BigInt;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::Modulo;
use sha2::{Sha256, Digest};
// use paillier::{KeyGeneration, Paillier};
use crate::utilities::mta_2021::zkp_p::PiPProver;

pub struct QRProof {
    pub a: BigInt,
    pub z: BigInt,
}

// Qudratic Residue proof 
// input n0, x, h

pub fn qr_verifier_setup() -> BigInt {
    let keypair = PiPProver::generate_paillier_blum_primes(3072);
    let n0 = keypair.n.clone();
    // let (ek0, _) = Paillier::keypair_with_modulus_size(3072).keys();
    // let n0 = ek0.n.clone();

    n0
}

pub fn qr_prover_setup(n0: &BigInt, )  -> (BigInt, BigInt) {
    let x: BigInt = BigInt::sample_below(&n0);
    let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);

    (x, h)
}

pub fn generate_zkp_qr(n0: &BigInt, x: &BigInt, h: &BigInt, ) -> QRProof {
    let r: BigInt = BigInt::sample_below(&n0);
    let a: BigInt = BigInt::mod_pow(&r, &BigInt::from(2), n0);

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

    QRProof {a, z}
}

pub fn verify_zkp_qr(zkp_qr: &QRProof, n0: &BigInt, h:&BigInt, ) -> bool {
    // let QRProof {a, z} = zkp_qr; // a, z
    let &QRProof {ref a, ref z} = zkp_qr;

    let mut hasher = Sha256::default();
    hasher.update(a.to_string().as_bytes());
    hasher.update(&h.to_string().as_bytes()); 
    let result = hasher.finalize();
    let last_byte = result[result.len() - 1];
    let e = if last_byte & 1 == 1{
        BigInt::from(1)
    } else {
        BigInt::from(0)
    }; //e

    let lhs = BigInt::mod_pow(&z, &BigInt::from(2), &n0); // z^2
    let rhs = BigInt::mod_mul( // h^e * a 
        &(BigInt::mod_pow(&h, &e, &n0)),
        &a,
        &n0,
    );

    println!("Verification_qr result: {}", lhs == rhs);

    lhs == rhs

}

#[test]
pub fn test_zkp_qr() {
    let n0 = qr_verifier_setup();
    let (x, h) = qr_prover_setup(&n0);
    let zkp_qr = generate_zkp_qr(&n0, &x, &h);
    let verified_qr = verify_zkp_qr(&zkp_qr, &n0, &h);
    assert!(verified_qr, "ZKPoKQR verification failed!")
}