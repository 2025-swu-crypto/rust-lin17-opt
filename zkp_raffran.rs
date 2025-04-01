use curv::arithmetic::traits::*;
use curv::BigInt;
use sha2::{Sha256, Digest};
use paillier::{Paillier, KeyGeneration};

#[drive(Clone)]
pub struct ProverRAffRan {
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
    pub ca: BigInt,
    pub cb: BigInt,
}

pub struct ProofRAffRan {}