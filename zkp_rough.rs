// ver.1 === 

// use curv::BigInt;
// // use paillier::*;
// use paillier::traits::*;
// use paillier::{RawPlaintext, RawCiphertext};
// use curv::arithmetic::traits::Samplable;
// use curv::arithmetic::Modulo;
// use curv::arithmetic::Converter;
// use sha2::{Sha256, Digest};
// use paillier::{Paillier, KeyGeneration, EncryptionKey, DecryptionKey};


// fn hash_to_bigint(inputs: &[&BigInt]) -> BigInt {
//     let mut hasher = Sha256::default();
//     for input in inputs {
//         hasher.update(&input.to_bytes());
//     }
//     let hash = hasher.finalize();
//     BigInt::from_bytes(&hash)
// }
// #[derive(Clone)]
// // 공개값
// struct MtAStatement {
//     pub ek: EncryptionKey,
//     pub a: BigInt,
//     pub ciphertext: BigInt,
// }

// #[derive(Clone)]
// // 비밀값
// struct MtAWitness {
//     pub b: BigInt,
//     pub r: BigInt,
// }

// #[derive(Clone)]
// // 증명
// struct MtAProof {
//     pub t: BigInt,
//     pub z_b: BigInt,
//     pub z_r: BigInt,
// }

// impl MtAStatement {
//     // 증명 생성 (P2가 수행)
//     pub fn prove(&self, witness: &MtAWitness) -> MtAProof {
//         let alpha = BigInt::sample_below(&self.ek.n);
//         let rho = BigInt::sample_below(&self.ek.n);

//         let t_msg = &self.a * &alpha + &rho;
//         let t = Paillier::encrypt(&self.ek, RawPlaintext::from(t_msg)).0.0.clone();

//         let e = hash_to_bigint(&[&self.ek.n, &self.a, &self.ciphertext, &t]);

//         let z_b = &alpha + &e * &witness.b;
//         let z_r = &rho + &e * &witness.r;

//         MtAProof { t, z_b, z_r }
//     }

//     // 증명 검증 (P1이 수행)
//     pub fn verify(&self, proof: &MtAProof) -> bool {
//         let e = hash_to_bigint(&[&self.ek.n, &self.a, &self.ciphertext, &proof.t]);

//         let left_msg = &self.a * &proof.z_b + &proof.z_r;
//         let left = Paillier::encrypt(&self.ek, RawPlaintext::from(left_msg));

//         let right = (&proof.t * BigInt::mod_pow(&self.ciphertext, &e, &self.ek.nn)) % &self.ek.nn;

//         println!("🔍 left  = {}", left);
//         println!("🔍 right = {}", right);

//         left == right
//     }
// }

// #[test]
// fn test() {
//     // 🅿️ P1: Paillier 키 생성
//     let (ek, _dk) = Paillier::keypair().keys();

//     let a = BigInt::from(123); // P1의 비밀값
//     let b = BigInt::from(456); // P2의 비밀값

//     // 🅿️ P2: r 샘플링 후 Enc(a * b + r) 계산
//     let r = BigInt::sample_below(&ek.n);
//     let m = &a * &b + &r;
//     let c = Paillier::encrypt(&ek, RawPlaintext::from(m.clone()));

//     // 📜 공개값 정의
//     let statement = MtAStatement {
//         ek: ek.clone(),
//         a: a.clone(),
//         ciphertext: c.clone(),
//     };

//     // 🔐 비밀값 정의 (b, r)
//     let witness = MtAWitness {
//         b: b.clone(),
//         r: r.clone(),
//     };

//     // 📤 P2 → ZK 증명 생성
//     let proof = statement.prove(&witness);

//     // 📥 P1 → ZK 증명 검증
//     let valid = statement.verify(&proof);

//     println!("\n✅ 증명 결과: {}", valid);
// }


// ver.2 === ZKPoK Full Suite: C.3.1 ~ C.3.4 Implementation ===

use num_bigint::BigInt;
use sha2::{Sha256, Digest};
use paillier::*;

// C.3.1 ZKPoK of QR
#[derive(Clone)]
pub struct ZkProofQR {
    pub n0: BigInt,
    pub x: BigInt,
    pub r: BigInt,
}

impl ZkProofQR {
    pub fn compute_h(&self) -> BigInt {
        BigInt::mod_pow(&self.x, &BigInt::from(2), &self.n0)
    }

    pub fn generate_commitment(&self) -> (BigInt, BigInt) {
        let a = BigInt::mod_pow(&self.r, &BigInt::from(2), &self.n0);
        (self.r.clone(), a)
    }

    pub fn generate_challenge(&self, a: &BigInt, h: &BigInt) -> BigInt {
        let mut hasher = Sha256::new();
        hasher.update(a.to_string().as_bytes());
        hasher.update(h.to_string().as_bytes());
        let hash = hasher.finalize();
        BigInt::from(hash[hash.len() - 1] & 1)
    }

    pub fn generate_response(&self, e: &BigInt) -> BigInt {
        let xe = BigInt::mod_pow(&self.x, e, &self.n0);
        BigInt::mod_mul(&xe, &self.r, &self.n0)
    }
}

// C.3.2 ZKPoK of QRDL
#[derive(Clone)]
pub struct ZkProofQRDL {
    pub g: BigInt,
    pub h: BigInt,
    pub alpha: BigInt,
    pub n0: BigInt,
}

impl ZkProofQRDL {
    pub fn generate_commitment(&self) -> (BigInt, BigInt) {
        let beta = BigInt::sample_below(&self.n0);
        let a = BigInt::mod_pow(&self.h, &beta, &self.n0);
        (beta, a)
    }

    pub fn generate_challenge(&self, a: &BigInt) -> BigInt {
        let mut hasher = Sha256::new();
        hasher.update(a.to_string().as_bytes());
        hasher.update(self.g.to_string().as_bytes());
        let hash = hasher.finalize();
        BigInt::from(hash[hash.len() - 1] & 1)
    }

    pub fn generate_response(&self, e: &BigInt, beta: &BigInt) -> BigInt {
        e * &self.alpha + beta
    }
}

// C.3.3 ZKPoKRPwR
#[derive(Clone)]
pub struct ZkProofRPwR {
    pub proof: ZkProofQR,
    pub proof_dl: ZkProofQRDL,
    pub y: BigInt,
    pub rd: BigInt,
    pub beta: BigInt,
    pub n: BigInt,
    pub n_square: BigInt,
}

impl ZkProofRPwR {
    pub fn commit(&self) -> (BigInt, BigInt, BigInt) {
        let capital_c = BigInt::mod_mul(
            &BigInt::mod_pow(&self.proof_dl.g, &self.proof.x, &self.proof.n0),
            &BigInt::mod_pow(&self.proof.h, &self.proof_dl.alpha, &self.proof.n0),
            &self.proof.n0,
        );

        let d = BigInt::mod_mul(
            &BigInt::mod_pow(&self.rd, &self.n, &self.n_square),
            &BigInt::mod_pow(&(BigInt::from(1) + &self.n), &self.y, &self.n_square),
            &self.n_square,
        );

        let capital_d = BigInt::mod_mul(
            &BigInt::mod_pow(&self.proof_dl.g, &self.y, &self.proof.n0),
            &BigInt::mod_pow(&self.proof.h, &self.beta, &self.proof.n0),
            &self.proof.n0,
        );

        (capital_c, d, capital_d)
    }

    pub fn challenge(&self, c: &BigInt, d: &BigInt, cd: &BigInt, t: u32) -> BigInt {
        let mut hasher = Sha256::new();
        hasher.update(c.to_string().as_bytes());
        hasher.update(d.to_string().as_bytes());
        hasher.update(cd.to_string().as_bytes());
        let hash = hasher.finalize();
        BigInt::from_bytes(&hash) % BigInt::from(2).pow(t)
    }

    pub fn response(&self, e: &BigInt) -> (BigInt, BigInt, BigInt) {
        let z1 = &self.y + &(e * &self.proof.x);
        let z2 = BigInt::mod_mul(&self.rd, &BigInt::mod_pow(&self.proof.r, e, &self.n_square), &self.n_square);
        let z3 = &self.beta + &(e * &self.proof_dl.alpha);
        (z1, z2, z3)
    }
}

// C.3.4 ZKPoKRP
#[derive(Clone)]
pub struct ZkProofRP {
    pub chunks: Vec<ZkProofRPwR>,
    pub e: BigInt,
}

impl ZkProofRP {
    pub fn generate(chunks: Vec<ZkProofRPwR>, t: u32) -> Self {
        let mut hasher = Sha256::new();
        for chunk in &chunks {
            let (c, d, cd) = chunk.commit();
            hasher.update(c.to_string().as_bytes());
            hasher.update(d.to_string().as_bytes());
            hasher.update(cd.to_string().as_bytes());
        }
        let hash = hasher.finalize();
        let e = BigInt::from_bytes(&hash) % BigInt::from(2).pow(t);
        Self { chunks, e }
    }

    pub fn responses(&self) -> Vec<(BigInt, BigInt, BigInt)> {
        self.chunks.iter().map(|c| c.response(&self.e)).collect()
    }
}
