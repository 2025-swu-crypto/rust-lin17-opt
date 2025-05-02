use curv::arithmetic::BigInt;
use curv::arithmetic::traits::*;
use curv::arithmetic::Modulo;
use curv::arithmetic::One;
use paillier::PrimeSampable;
use sha2::{Sha256, Digest};

// use crate::utilities::mta_2021::PartyTwo;

pub const L: usize = 5;

// common input = n
// prover has secret input (p, q) s.t. n = pq
#[derive(Clone, Debug)] 
pub struct PiPProver {
    pub n: BigInt,
    p: BigInt,
    q: BigInt,
}

pub struct PiPProof {
    pub w: BigInt,
    pub x_vec: Vec<BigInt>,
    pub a_vec: Vec<u8>,
    pub b_vec: Vec<u8>,
    pub z_vec: Vec<BigInt>,
}

/// Sha256 기반 PRG 체인 y₀ = H(n || w), yᵢ = H(yᵢ₋₁)
pub fn generate_yi_vec(n: &BigInt, w: &BigInt) -> Vec<BigInt> {
    let mut y_vec: Vec<BigInt> = Vec::with_capacity(L);

    // 1. 시드: n || w
    let mut seed = Sha256::new();
    seed.update(n.to_bytes());
    seed.update(w.to_bytes());

    let mut y_i = BigInt::from_bytes(&seed.finalize()).modulus(n);
    y_vec.push(y_i.clone());

    // 2. 반복: yᵢ = H(yᵢ₋₁)
    for _ in 1..L {
        y_i = BigInt::from_bytes(&Sha256::digest(&y_i.to_bytes())).modulus(n);
        // print_yi_in_loop(i, &y_i);
        y_vec.push(y_i.clone());
    }

    y_vec
}

impl PiPProver {
    pub fn new(n: BigInt, p: BigInt, q: BigInt,) -> PiPProver {
        PiPProver { n, p, q }
    }

    pub fn get_p(&self) -> &BigInt {
        &self.p
    }

    pub fn get_q(&self) -> &BigInt {
        &self.q
    }

    pub fn generate_paillier_blum_primes(bit_len: usize) -> Self { 
        // let upper = BigInt::from(1) << (bit_len / 2);
        loop {
            let p = BigInt::sample_prime(bit_len / 2);
            if &p % 4 != BigInt::from(3) {
                continue;
            }

            let q = BigInt::sample_prime(bit_len / 2);
            if &q % 4 != BigInt::from(3) {
                continue;
            }
            if BigInt::gcd(&p, &q) != BigInt::one() {
                continue;
            } // check that p and q are coprime (ensures q^-1 mod p exists)

            let n = &p * &q;
            let phi_n = (&p - BigInt::one()) * (&q - BigInt::one());
            if BigInt::gcd(&n, &phi_n) != BigInt::one() {
                continue; // N과 φ(N)이 서로소가 아니라면 다시 샘플링
            }

            return Self {n, p, q};
        } // mod 4에서 3이되는 prime(p, q) 선정 -> n = pq
    }


    pub fn sample_w(n: &BigInt,) -> BigInt { // w, n jacobi == -1 인 w 반환
        loop {
            let w = BigInt::sample_below(n);
            if BigInt::jacobi(&w, &n) == -1 { // w.gcd(&n) != BigInt::one() && 
                return w;
            }
        }
    }
       
    pub fn compute_yi_prime_ai_bi(
        &self, 
        y_i: &BigInt,
        w: &BigInt,
    ) -> (u8, u8, BigInt) {        
        let jacoobi_yp = BigInt::jacobi(y_i, &self.p);
        let jacoobi_yq = BigInt::jacobi(y_i, &self.q);
        let jacoobi_wp = BigInt::jacobi(&w, &self.p);
        let jacoobi_wq = BigInt::jacobi(&w, &self.q);
        
        let (a, b) = if jacoobi_wp == 1 && jacoobi_wq == -1 {
            match (jacoobi_yp, jacoobi_yq) {
                (1, 1)   => (0, 0),
                (1, -1)  => (0, 1),
                (-1, 1)  => (1, 1),
                (-1, -1) => (1, 0),
                _ => panic!("Invalid Jacobi combination"),
            }
        } else {
            match (jacoobi_yp, jacoobi_yq) {
                (1, 1)   => (0, 0),
                (1, -1)  => (1, 1),
                (-1, 1)  => (0, 1),
                (-1, -1) => (1, 0),
                _ => panic!("Invalid Jacobi combination"),
            }
        };

        // println!("\n0. a:{}, b:{}, [y_i]:{:?}\n   l_p:{}, l_q:{}", a, b, y_i, jacoobi_yp, jacoobi_yq);

        let mut yi_prime = y_i.clone();
        // let jacoobi_yp = BigInt::jacobi(&yi_prime, &self.p);
        // let jacoobi_yq = BigInt::jacobi(&yi_prime, &self.q);
        // println!("1. a:{}, b:{}, [y_i]:{:?}\n   l_p_i:{}, l_q_i:{}", a, b, yi_prime, jacoobi_yp, jacoobi_yq);

        if b == 1 {
            yi_prime = BigInt::mod_mul(&yi_prime, w, &self.n);
        }
        // let jacoobi_yp = BigInt::jacobi(&yi_prime, &self.p);
        // let jacoobi_yq = BigInt::jacobi(&yi_prime, &self.q);
        // println!("2. a:{}, b:{}, [y_i]:{:?}\n   l_p_i:{}, l_q_i:{}", a, b, yi_prime, jacoobi_yp, jacoobi_yq);

        if a == 1 {
            yi_prime = &self.n - (&yi_prime % &self.n);
        }
        // let jacoobi_yp = BigInt::jacobi(&yi_prime, &self.p);
        // let jacoobi_yq = BigInt::jacobi(&yi_prime, &self.q);
        // println!("3. a:{}, b:{}, [y_i]:{:?}\n   l_p_i:{}, l_q_i:{}", a, b, yi_prime, jacoobi_yp, jacoobi_yq);

        // let jacoobi_yp = BigInt::jacobi(&yi_prime, &self.p);
        // let jacoobi_yq = BigInt::jacobi(&yi_prime, &self.q);
        // println!("4. a:{}, b:{}, [compute_yi_prime]:{:?}\n   l_p_i:{}, l_q_i:{}", a, b, yi_prime, jacoobi_yp, jacoobi_yq);

        (a, b, yi_prime)
    }
    
    pub fn compute_xi_crt(
        &self, 
        yi_prime: &BigInt, 
    ) -> BigInt {
        let exp_p = (&self.p + BigInt::one()) >> 2; // p + 1 / 4 quotient
        let exp_q = (&self.q + BigInt::one()) >> 2; // q + 1 / 4 quotient

        let yiprime_p = BigInt::mod_pow(yi_prime, &exp_p, &self.p);
        let yiprime_q = BigInt::mod_pow(yi_prime, &exp_q, &self.q);

        let inv_p = BigInt::mod_inv(&self.p, &self.q).expect("p^-1 mod q must exist"); // p를 q에서 inv
        let inv_q = BigInt::mod_inv(&self.q, &self.p).expect("q^-1 mod p must exist"); // q를 p에서 inv

        let pp = BigInt::mod_mul(&self.p, &inv_p, &self.n);
        let qq = BigInt::mod_mul(&self.q, &inv_q, &self.n);
        // let pp = self.p * inv_p;
        // let qq = self.q * inv_q;

        let term1 = BigInt::mod_mul(
            &(BigInt::mod_pow(&yiprime_p, & exp_p, &self.p)),
            &qq,
            &self.n,
        );
        let term2 = BigInt::mod_mul(
            &(BigInt::mod_pow(&yiprime_q, &exp_q, &self.q)),
            &pp,
            &self.n,
        ); 
        let x = BigInt::mod_add(&term1, &term2, &self.n);
        // let x4 = BigInt::mod_pow(&x, &BigInt::from(4), &self.n);
        // println!("[prover] x: {}\n", x);
        // let _x4 = x.pow(4).modulus(&self.n);
        // println!("[prover] x4: {}\n", x4);
        // println!("[prover] _x4: {}\n", _x4);
        // if _x4 != x4 {
            // println!("false");
            // println!("[prover] x4: {}\n", x4);
            // println!("[prover] _x4: {}\n", _x4);
        // }
        x
    }

    pub fn compute_zi(
        &self,
        phi_n: &BigInt,
        y: &BigInt, 
    ) -> BigInt {
        let inv_n = BigInt::mod_inv(&self.n, &phi_n).expect("N must be invertible mod φ(N)");

        BigInt::mod_pow(y, &inv_n, &self.n)
    } 
    
    pub fn print_w_and_jacobi(&self, w: &BigInt,) {
        let jacobi_wp = BigInt::jacobi(w, &self.p);
        let jacobi_wq = BigInt::jacobi(w, &self.q);
        println!("w        = {}", w);
        println!("Jacobi(w, p) = {}", jacobi_wp);
        println!("Jacobi(w, q) = {}", jacobi_wq);
    
        assert_eq!(jacobi_wp * jacobi_wq, -1, "❌ Jacobi(w, n) ≠ -1");
        println!("✅ Jacobi(w, n) = -1 ✔");
    }

    pub fn generate_pip_proof(
        &self,
    ) -> PiPProof {
        // BigInt, Vec<BigInt>, Vec<u8>, Vec<u8>, Vec<BigInt>
        let w = PiPProver::sample_w(&self.n);
        let y_vec = generate_yi_vec(&self.n, &w);
        let phi_n = (self.p.clone() - 1) * (self.q.clone() - 1);

        let mut yi_prime_vec = Vec::with_capacity(y_vec.len());
        let mut x_vec = Vec::with_capacity(y_vec.len());
        let mut a_vec = Vec::with_capacity(y_vec.len());
        let mut b_vec = Vec::with_capacity(y_vec.len());
        let mut z_vec = Vec::with_capacity(y_vec.len());
    
        for y_i in &y_vec {
            let (a, b, yi_prime) = PiPProver::compute_yi_prime_ai_bi(self, &y_i, &w);
            let x_i = PiPProver::compute_xi_crt(self, &yi_prime);
            let z_i = self.compute_zi(&phi_n, &y_i);

            yi_prime_vec.push(yi_prime);
            x_vec.push(x_i);
            a_vec.push(a);
            b_vec.push(b);
            z_vec.push(z_i);
        }

        // check_yi_prime_correctness(&y_vec, &a_vec, &b_vec, &yi_prime_vec, &w, &self.n);

        PiPProof {w, x_vec, a_vec, b_vec, z_vec}
    } // yi_prime 비반환 버전
}

pub fn verify_pip_proof(
    n: &BigInt, 
    proof: &PiPProof, 
) -> bool {
    if n.is_even() || n.is_probable_prime(10) {
        return false;
    }

    let y_vec = generate_yi_vec(n, &proof.w); // Verifier's y_vec 생성

    for i in 0..L {
        let y_i = &y_vec[i];
        let x_i = &proof.x_vec[i];
        let a_i = proof.a_vec[i];
        let b_i = proof.b_vec[i];
        let z_i = &proof.z_vec[i];

        // 1. z_i^N mod N == y_i
        let z = BigInt::mod_pow(z_i, n, n);
        if z != *y_i {
            println!("❌ z[{}]^N, y[{}] are not same", i, i);
            return false;
        }

        // 2. x_i^4 == (-1)^a_i * w^b_i * y_i
        let mut yi_prime = y_i.clone();
        if b_i == 1 {
            yi_prime = BigInt::mod_mul(&yi_prime, &proof.w, n);
        }
        if a_i == 1 {
            yi_prime = n - (&yi_prime % n);
        }

        // println!("--- i = {} ---", i);
        // println!("a = {}, b = {}", a_i, b_i);
        // println!("[verifier] y'[{}]     = {}", i, yi_prime);
        // -> verifier's yi_prime check

        // println!("a_{}, b_{}    = {}, {}", i, i, a_i, b_i);
        let x4 = BigInt::mod_pow(x_i, &BigInt::from(4), n);
        if x4 != yi_prime {
        //     println!("--- i = {} ---", i);
        println!("❌ x4[{}] != expected yi_prime'", i);
            // println!("[verifier] x4:{}", x4);
            // println!("[verifier] yi_prime:{}", yi_prime);
            // println!("y_{}          = {}", i, y_i);
            // println!("x_{}          = {}", i, x_i);
            return false;
        }
    }

    true
}

#[test]
pub fn test_pip_proof() {
    // let p2 = PartyTwo::new();
    let prover_pip = PiPProver::generate_paillier_blum_primes(3072); // p, q, n
    let n = &prover_pip.n;
    let PiPProof {w, x_vec, a_vec, b_vec, z_vec} = prover_pip.generate_pip_proof();
    let proof = PiPProof {
        w,
        x_vec: x_vec.clone(),
        a_vec,
        b_vec,
        z_vec,
    };

    assert!(verify_pip_proof(n, &proof));
}