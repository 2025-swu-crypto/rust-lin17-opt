// use std::hash::BuildHasherDefault;

use curv::BigInt;
use curv::arithmetic::One;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{BasicOps, Modulo, Converter};

// use paillier::serialize::bigint;
use sha2::{Sha256, Digest};

use paillier::{KeyGeneration, Paillier};

pub const S: u32 = 128;
pub const T: u32 = 128;
pub const L: u32 = 80;

pub struct ProofQR {
    a: BigInt,
    z: BigInt,
}
pub struct ProofQRdl {
    a: BigInt,
    z: BigInt,
}
pub struct ProofRPwR {
    capital_c: BigInt,
    pub d: BigInt,
    pub capital_d: BigInt,
    pub z1: BigInt,
    pub z2: BigInt,
    pub z3: BigInt,
}
pub struct ProofAffRan {
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

pub fn prover_init(n0: &BigInt, ) -> (BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, BigInt, ) {
    let (ek, dk) = Paillier::keypair_with_modulus_size(3072).keys();
    let n = ek.n.clone();
    let q = dk.q.clone();
    let nn = n.clone() * n.clone();

    let x: BigInt = BigInt::sample_below(&(&q / BigInt::from(3)));
    let h = BigInt::mod_pow(&x, &BigInt::from(2), &n);

    let alpha: BigInt = BigInt::sample_below(&n0);
    let g = BigInt::mod_pow(&h, &alpha, &n0);

    let r: BigInt = BigInt::sample_below(&n0);
    let c: BigInt = BigInt::mod_mul(
        &BigInt::mod_pow(&r, &n, &nn),
        &BigInt::mod_pow(&(BigInt::from(1) + n.clone()), &x, &nn),
        &nn
        );

    (n, nn, q, x, h, alpha, g, r, c, )
}

pub fn prover_second(n: &BigInt, nn: &BigInt, q: &BigInt, c: &BigInt, ) -> (BigInt, BigInt, BigInt) {
    let k_big: BigInt = BigInt::from(2).pow(T+L+S) * q.pow(2);
    let b = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * q.clone()));
    let beta = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * k_big));
    let cb = BigInt::mod_mul(
        &(BigInt::mod_pow(&c, &b, &nn)),
        &(BigInt::one() + n.clone() * beta.clone()), // 여기서 beta 의 범위 증명
        &nn
    );
    println!("b: {}", b);
    println!("beta: {}", beta);
    println!("cb: {}", cb);
    (b, beta, cb)
}

pub fn verifier_init() -> (BigInt, BigInt) {
    let (ek0, dk0) = Paillier::keypair_with_modulus_size(3072).keys();
    let n0 = ek0.n.clone();
    let q0 = dk0.q.clone();

    (n0, q0)
}

pub fn verifier_second(n0: &BigInt, q0: &BigInt, n: &BigInt, nn: &BigInt, q: &BigInt, c: &BigInt, ) -> (BigInt, BigInt, BigInt, BigInt, BigInt) {
    let k_big: BigInt = BigInt::from(2).pow(T+L+S) * q.pow(2);
    let a = BigInt::sample_below(&(q.clone() / BigInt::from(3)));
    let alpha = BigInt::sample_below(&(k_big.clone() / BigInt::from(3)));
    let x0 = BigInt::sample_below(&(q0 / BigInt::from(3)));
    let h0 = BigInt::mod_pow(&x0, &BigInt::from(2), &n0);
    let g0 = BigInt::mod_pow(&h0, &alpha, &n0);

    let ca = BigInt::mod_mul(
        &(BigInt::mod_pow(&c, &a, &nn)),
        &(BigInt::one() + n.clone() * alpha.clone()),
        &nn
    );
    println!("a: {}", a);
    println!("alpha: {}", alpha);
    println!("ca: {}", ca);
    (h0, g0, a, alpha, ca)
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

pub fn zkp_qr_verifier(proof: &ProofQR, n0: &BigInt, h:&BigInt, ) -> bool {
    let ProofQR {a, z} = proof; // a, z

    let mut hasher = Sha256::default();
    hasher.update(&proof.a.to_string().as_bytes());
    hasher.update(&h.to_string().as_bytes()); 
    let result = hasher.finalize();
    let last_byte = result[result.len() - 1];
    let e = if last_byte & 1 == 1{
        BigInt::from(1)
    } else {
        BigInt::from(0)
    }; //e

    let lhs = BigInt::mod_pow(&proof.z, &BigInt::from(2), &n0); // z^2
    let rhs = BigInt::mod_mul( // h^e * a 
        &(BigInt::mod_pow(&h, &e, &n0)),
        &proof.a,
        &n0,
    );

    println!("Verification_qr result: {}", lhs==rhs);

    lhs == rhs

}

pub fn zkp_qrdl_prover(n0: &BigInt, h: &BigInt, g: &BigInt, alpha: &BigInt, ) -> ProofQRdl {
    let beta = BigInt::sample_range(&BigInt::from(1), &(BigInt::from(2).pow(S-1) * n0)) * 2;
    let a: BigInt = BigInt::mod_pow(&h, &beta, &n0); // h^beta

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

pub fn zkp_qrdl_verifier(proof: &ProofQRdl, n0: &BigInt, g: &BigInt, h: &BigInt, ) -> bool {
    let ProofQRdl {a, z} = proof;
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

    let lhs = BigInt::mod_pow(&h, &proof.z, &n0);
    let rhs = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &e, &n0)),
        &proof.a,
        &n0,
    );

    println!("Verification_qrdl result: {}", lhs == rhs);

    lhs == rhs
}

pub fn zkp_range_proof_prover(n0: &BigInt, n: &BigInt, nn: &BigInt, q: &BigInt, h: &BigInt, g: &BigInt, x: &BigInt, r: &BigInt, c: &BigInt, ) -> ProofRPwR {
    let alpha = BigInt::sample_below(&n0);
    let beta = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n0));
    let y = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * q));
    let rd = BigInt::sample_below(&n);
    let capital_c = BigInt::mod_mul(
        &BigInt::mod_pow(&g, &x, &n0),
        &BigInt::mod_pow(&h, &alpha, &n0),
        &n0,
    );
    let d = BigInt::mod_mul(
        &BigInt::mod_pow(&rd, &n, &nn),
        // &BigInt::mod_pow(&(BigInt::from(1) + n.clone()), &y, &nn),
        &((BigInt::one() + n * y.clone()) % nn),
        &nn,
    );
    let capital_d = BigInt::mod_mul(
        &BigInt::mod_pow(&g, &y, &n0),
        &BigInt::mod_pow(&h, &beta, &n0),
        &n0,
    );

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

    let z1 = &y + (e.clone() * x.clone()); // integer
    let z2 = BigInt::mod_mul(
        &rd,
        &BigInt::mod_pow(&r, &e.clone(), &nn),
        &nn,
    );
    let z3 = beta.clone() + (alpha.clone() * e.clone()); // integer

    ProofRPwR {capital_c, d, capital_d, z1, z2, z3}
}

pub fn zkp_range_proof_verifier(proof: &ProofRPwR, n0: &BigInt, n: &BigInt, nn: &BigInt, q: &BigInt, h: &BigInt, g: &BigInt, c: &BigInt, ) -> bool {
    let ProofRPwR {capital_c, d, capital_d, z1, z2, z3,} = proof;
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

    let lhs1 = BigInt::mod_mul(
        &BigInt::mod_pow(&proof.z2, n, nn),
        // &BigInt::mod_pow(&(BigInt::from(1) + n), &proof.z1, nn),
        &((BigInt::one() + n * proof.z1.clone()) % nn),
        nn,
    );
    let rhs1 = BigInt::mod_mul(
        &proof.d,
        &BigInt::mod_pow(&c, &e, nn), 
        nn
    );

    let lhs2 = BigInt::mod_mul(
        &BigInt::mod_pow(&g, &proof.z1, &n0),
        &BigInt::mod_pow(&h, &proof.z3, &n0),
        &n0,
    );
    let rhs2 = BigInt::mod_mul(
        &proof.capital_d,
        &BigInt::mod_pow(&proof.capital_c, &e, &n0),
        &n0,
    );

    let verif3 = 
    z1 >= &(BigInt::from(2).pow(T) * q) &&
    z1 < &{BigInt::from(2).pow(T + L) * q};

    println!("Verification_rpwr result: {}, {}, {}", lhs1==rhs1, lhs2 == rhs2, verif3);

    lhs1 == rhs1 && lhs2 == rhs2 && verif3
}

// Paillier Encryption witn range proof
pub fn zkp_affran_prover(n0: &BigInt, n: &BigInt, nn: &BigInt, h: &BigInt, g: &BigInt, a: &BigInt, alpha: &BigInt, b: &BigInt, beta: &BigInt, c: &BigInt, ) -> ProofAffRan {
   
    let rho1 = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n0));
    let rho2 = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n0));
    let rho3 = BigInt::sample_below(&(n0));
    let rho4 = BigInt::sample_below(&(n0));

    let capital_a = BigInt::mod_mul(
        &(BigInt::mod_pow(&c, &b, &nn)),
        &((BigInt::one() + n * beta.clone()) % nn),
        &nn
    );
    let capital_b1 = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &b, &n0)),
        &(BigInt::mod_pow(&h, &rho3, &n0)),
        &n0
    );
    let capital_b2 = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &beta, &n0)),
        &(BigInt::mod_pow(&h, &rho2, &n0)),
        &n0
    );
    let capital_b3 = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &a, &n0)),
        &(BigInt::mod_pow(&h, &rho3, &n0)),
        &n0
    );
    let capital_b4 = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &alpha, &n0)),
        &(BigInt::mod_pow(&h, &rho4, &n0)),
        &n0
    );

    let mut hasher = Sha256::new();
    hasher.update(capital_a.to_string().as_bytes());
    hasher.update(capital_b1.to_string().as_bytes());
    hasher.update(capital_b2.to_string().as_bytes());
    hasher.update(capital_b3.to_string().as_bytes());
    hasher.update(capital_b4.to_string().as_bytes());
    let result = hasher.finalize();
    let modulus: BigInt = BigInt::from(2).pow(T);
    let e = BigInt::from_bytes(&result) % modulus;

    let z1 = b + e.clone() * a;
    let z2 = beta + e.clone() * alpha;
    let z3 = rho1 + e.clone() * rho3;
    let z4 = rho2 + e.clone() * rho4;

    ProofAffRan {capital_a, capital_b1, capital_b2, capital_b3, capital_b4, z1, z2, z3, z4}
}

pub fn zkp_affran_verifier(proof: &ProofAffRan, n0: &BigInt, q: &BigInt, n: &BigInt, nn: &BigInt, h: &BigInt, g: &BigInt, c: &BigInt, ca: &BigInt, ) -> bool {
    let big_k: BigInt = BigInt::from(2).pow(T+L+S) * q.pow(2);
    let ProofAffRan {capital_a, capital_b1, capital_b2, capital_b3, capital_b4, z1, z2, z3, z4 } = proof;
    let mut hasher = Sha256::new();
    hasher.update(capital_a.to_string().as_bytes());
    hasher.update(capital_b1.to_string().as_bytes());
    hasher.update(capital_b2.to_string().as_bytes());
    hasher.update(capital_b3.to_string().as_bytes());
    hasher.update(capital_b4.to_string().as_bytes());
    let result = hasher.finalize();
    let modulus: BigInt = BigInt::from(2).pow(T);
    let e = BigInt::from_bytes(&result) % modulus;

    let verif1 = 
    z1 >= &(BigInt::from(2).pow(T) * q) && 
    z1 < &(BigInt::from(2).pow(T+L) * q);
    let verif2 = 
    z2 >= &(BigInt::from(2).pow(T) * big_k.clone()) &&
    z2 < &(BigInt::from(2).pow(T+L) * big_k.clone());
    let lhs3 = BigInt::mod_mul(
        &(BigInt::mod_pow(&c, &proof.z1, &nn)),
        &(BigInt::one() + n * proof.z2.clone()), 
        &nn
    );
    let rhs3 = BigInt::mod_mul(
        &proof.capital_a,
        &(BigInt::mod_pow(&ca, &e, &nn)),
        &nn,
    );
    // let verif3 = lhs3 == rhs3;
    let lhs4 = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &proof.z1, &n0)),
        &(BigInt::mod_pow(&h, &proof.z3, &n0)),
        &n0
    );
    let rhs4 = BigInt::mod_mul(
        &proof.capital_b1,
        &(BigInt::mod_pow(&proof.capital_b3, &e, &n0)),
        &n0
    );
    println!("lhs4: {}, \ng: {}, \nproof.z1: {}, \nn0: {}, \nh: {}, \nproof.z3: {}", lhs4, g, proof.z1, n0, h, proof.z3);
    println!("rhs4: {}, \nproof.capital_b1: {}, \nproof.capital_b3: {}, \ne: {}, \nn0: {}", rhs4, proof.capital_b1, proof.capital_b3, e, n0);



    // let verif4 = lhs4 == rhs4;
    let lhs5 = BigInt::mod_mul(
        &(BigInt::mod_pow(&g, &proof.z2, &n0)),
        &(BigInt::mod_pow(&h, &proof.z4, &n0)),
        &n0
    );
    let rhs5 = BigInt::mod_mul(
        &proof.capital_b2,
        &(BigInt::mod_pow(&proof.capital_b4, &e, &n0)),
        &n0
    );
    // let verif5 = lhs5 ==rhs5;

    println!("Verification_affran result: {}, {}, {}, {}, {}", verif1, verif2, lhs3 == rhs3, lhs4 == rhs4, lhs5 == rhs5);

    verif1 && verif2 && lhs3 == rhs3 && lhs4 == rhs4 && lhs5 == rhs5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_qr() {
        let (n0, _) = verifier_init();
        let (_, _, _, x, h, _, _, _, _, ) = prover_init(&n0);
        let proof = zkp_qr_prover(&n0, &h, &x);
        let verified_qr = zkp_qr_verifier(&proof, &n0, &h);
        assert!(verified_qr, "ZKPoKQR verification_qr failed!");
    }

    #[test]
    fn test_zkp_qrdl() {
        let (n0, _) = verifier_init();
        let (_, _, _, _, h, alpha, g, _, _, ) = prover_init(&n0);
        let proof = zkp_qrdl_prover(&n0, &h, &g, &alpha);
        let verified_qrdl = zkp_qrdl_verifier(&proof, &n0, &g, &h);
        assert!(verified_qrdl, "ZKPoKQR verification_qrdl failed!");
    }

    #[test]
    fn test_range_proof() {
        let (n0, _) = verifier_init();
        let (n, nn, q, x, h, _, g, r, c, ) = prover_init(&n0);
        let proof = zkp_range_proof_prover(&n0, &n, &nn, &q, &h, &g, &x, &r, &c);
        let verified = zkp_range_proof_verifier(&proof, &n0, &n, &nn, &q, &h, &g, &c);
        assert!(verified, "Range Proof for x failed!"); // verify for x in special q
    }

    #[test]
    fn test_affran() {
        let (n0, q0) = verifier_init();
        let (n, nn, q, _, h, _, g, _, c, ) = prover_init(&n0);
        let (b, beta, _) = prover_second(&n, &nn, &q, &c);
        let (_, _, a, alpha, ca) = verifier_second(&n0, &q0, &n, &nn, &q, &c);
        let proof = zkp_affran_prover(&n0, &n, &nn, &h, &g, &a, &alpha, &b, &beta, &c);
        let verified_affran = zkp_affran_verifier(&proof, &n0, &q, &n, &nn, &h, &g, &c, &ca,);
        assert!(verified_affran, "Paillier encryption witn range proof failed!");
    }
}