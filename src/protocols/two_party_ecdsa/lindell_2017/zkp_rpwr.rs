use curv::arithmetic::traits::*;
use curv::BigInt;
use sha2::{Sha256, Digest};
use paillier::{Paillier, KeyGeneration};

#[derive(Clone)]
pub struct ProverRPwR {
    pub n0: BigInt,
    pub x: BigInt,
    pub r: BigInt,
    pub h: BigInt,
    pub alpha: BigInt,
    pub beta: BigInt,
    pub g: BigInt,
    pub q: BigInt,
    pub n: BigInt,
    pub rd: BigInt,
    pub nn: BigInt, // n square
    pub y: BigInt,
    pub c: BigInt,
}

pub struct ProofRPwR {
    pub capital_c: BigInt,
    pub d: BigInt,
    pub capital_d: BigInt,
    pub z1: BigInt,
    pub z2: BigInt,
    pub z3: BigInt,
}


impl ProverRPwR {

    pub fn generate_init() -> ProverRPwR {

        let t: u32 = 128;
        let l: u32 = 80;

        let (ek, dk) = paillier::Paillier::keypair_safe_primes_with_modulus_size(3072).keys();
        let n0 = ek.n.clone();
        let x = BigInt::sample_below(&(dk.q.clone() / BigInt::from(3)));
        let r = BigInt::sample_below(&n0);
        let h = BigInt::mod_pow(&x, &BigInt::from(2), &n0);
        let alpha = BigInt::sample_below(&n0);
        let beta= BigInt::sample_below(&(BigInt::from(2).pow(t+l) * &n0));
        let g = BigInt::mod_pow(&h, &alpha, &n0);

        let (ek2, dk2) = Paillier::keypair_safe_primes_with_modulus_size(3072).keys();
        let q = dk2.q.clone();
        let n = ek2.n.clone();
        let rd: BigInt = BigInt::sample_below(&n);
        let nn = n.clone() * n.clone();
        let y = BigInt::sample_below(&(BigInt::from(2).pow(t+l) * &q));

        let c: BigInt = BigInt::mod_mul(
            &BigInt::mod_pow(&r, &n, &nn),
            &BigInt::mod_pow(&(BigInt::from(1) + &n), &x, &nn),
            &nn
            );

        ProverRPwR { n0, x, r , h, alpha, beta, g, q, n, rd, nn, y, c, }
    }

    pub fn prove(&self, q: &BigInt, t: u32, /*g: &BigInt, x: &BigInt, n0: &BigInt, h: &BigInt, alpha: &BigInt, rd: &BigInt, n: &BigInt, nn: &BigInt, y: &BigInt, beta: &BigInt,*/ ) -> ProofRPwR/*(BigInt, BigInt, BigInt, BigInt, BigInt, BigInt)*/ {
        
        let capital_c = BigInt::mod_mul(
            &BigInt::mod_pow(&self.g, &self.x, &self.n0),
            &BigInt::mod_pow(&self.h, &self.alpha, &self.n0),
            &self.n0,
        );

        let d = BigInt::mod_mul(
            &BigInt::mod_pow(&self.rd, &self.n, &self.nn),
            &BigInt::mod_pow(&(BigInt::from(1) + self.n.clone()), &self.y, &self.nn),
            &self.nn,
        );

        let capital_d = BigInt::mod_mul(
            &BigInt::mod_pow(&self.g, &self.y, &self.n0),
            &BigInt::mod_pow(&self.h, &self.beta, &self.n0),
            &self.n0,
        );

        let mut hasher = Sha256::new();

        hasher.update(self.n.to_string().as_bytes());
        hasher.update(q.to_string().as_bytes());
        hasher.update(self.c.to_string().as_bytes());
        hasher.update(capital_c.to_string().as_bytes());
        hasher.update(d.to_string().as_bytes());
        hasher.update(capital_d.to_string().as_bytes());
        let hash = hasher.finalize();
        let modulus = BigInt::from(2).pow(t);
        let e = BigInt::from_bytes(&hash) % modulus;

        let z1 = &self.y + (e.clone() * self.x.clone()); // integer
        let z2 = BigInt::mod_mul(
            &self.rd,
            &BigInt::mod_pow(&self.r, &e.clone(), &self.nn),
            &self.nn,
        );
        let z3 = self.beta.clone() + (self.alpha.clone() * e.clone()); // integer

        ProofRPwR {
            capital_c,
            d,
            capital_d,
            z1,
            z2,
            z3,
        }
    }

    // pub fn challenge(&self, /*n: &BigInt, q: &BigInt, c: &BigInt,*/ q: &BigInt, capital_c: &BigInt, d: &BigInt, capital_d: &BigInt, t: u32, ) -> BigInt {
    //     let mut hasher = Sha256::new();

    //     hasher.update(self.n.to_string().as_bytes());
    //     hasher.update(q.to_string().as_bytes());
    //     hasher.update(self.c.to_string().as_bytes());
    //     hasher.update(capital_c.to_string().as_bytes());
    //     hasher.update(d.to_string().as_bytes());
    //     hasher.update(capital_d.to_string().as_bytes());
    //     let hash = hasher.finalize();
    //     let modulus = BigInt::from(2).pow(t);
    //     let e = BigInt::from_bytes(&hash) % modulus;
    // }

    // pub fn response(&self, e: &BigInt, y: &BigInt, x: &BigInt, rd: &BigInt, r: &BigInt, nn: &BigInt,beta: &BigInt, alpha: &BigInt) -> (BigInt, BigInt, BigInt) {
    //     let z1 = y + (e * x); // integer
    //     let z2 = BigInt::mod_mul(
    //         &rd,
    //         &BigInt::mod_pow(&r, e, &nn),
    //         &nn,
    //     );
    //     let z3 = beta + (alpha * e); // integer
    //     (z1, z2, z3)
    // }
}

pub fn verify(
    z1: &BigInt,
    z2: &BigInt,
    z3: &BigInt,
    capital_c: &BigInt,
    d: &BigInt,
    capital_d: &BigInt,
    c: BigInt,
    h: &BigInt,
    n0: &BigInt,
    n: &BigInt,
    nn: &BigInt,
    g: &BigInt,
    t: u32,
    l: u32,
    q: &BigInt,
) -> bool {

    let mut hasher = Sha256::new();

        hasher.update(n.to_string().as_bytes());
        hasher.update(q.to_string().as_bytes());
        hasher.update(c.to_string().as_bytes());
        hasher.update(capital_c.to_string().as_bytes());
        hasher.update(d.to_string().as_bytes());
        hasher.update(capital_d.to_string().as_bytes());
        let hash = hasher.finalize();
        let modulus = BigInt::from(2).pow(t);
        let e = BigInt::from_bytes(&hash) % modulus;    

    let lhs1 = BigInt::mod_mul(
        &BigInt::mod_pow(z2, n, nn),
        &BigInt::mod_pow(&(BigInt::from(1) + n), z1, nn),
        nn,
    );
    let rhs1 = BigInt::mod_mul(
        d, 
        &BigInt::mod_pow(&c, &e, nn), 
        nn
    );

    let lhs2 = BigInt::mod_mul(
        &BigInt::mod_pow(g, z1, n0),
        &BigInt::mod_pow(h, z3, n0),
        n0,
    );
    let rhs2 = BigInt::mod_mul(
        capital_d,
        &BigInt::mod_pow(capital_c, &e, n0),
        n0,
    );

    let lower = BigInt::from(2).pow(t) * q;
    let upper = BigInt::from(2).pow(t + l) * q;
    let range_check_z1 = z1 >= &lower && z1 < &upper;

    println!("Verification_rpwr result: {}, {}, {}", lhs1==rhs1, lhs2 == rhs2, range_check_z1);

    lhs1 == rhs1 && lhs2 == rhs2 && range_check_z1
}

#[test]
fn test_rpwr() {
    let prover = ProverRPwR::generate_init();
    let t = 128;
    let l: u32 = 80;
    let proof = prover.prove(&prover.q, t);

    let result = verify(
        &proof.z1,
        &proof.z2,
        &proof.z3,
        &proof.capital_c,
        &proof.d,
        &proof.capital_d,
        prover.c.clone(),
        &prover.h,
        &prover.n0,
        &prover.n,
        &prover.nn,
        &prover.g,
        t,
        l,
        &prover.q,
    );

    assert!(result, "RPwR proof verification failed.");
}