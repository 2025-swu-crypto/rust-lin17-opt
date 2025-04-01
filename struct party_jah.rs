pub struct party1 {
    n0: BigInt, // pk
    g0: BigInt, // generator for party1
    h0: BigInt,
    alpha0: BigInt,
    beta0: BigInt,
    x0 : BigInt,
    r0: BigInt,
    enc_a: BigInt,
    pi_a: BigInt,
}

pub struct party2{
    n: BigInt,
    g: BigInt,
    h: BigInt,
    alpha: BigInt,
    beta: BigInt,
    x: BigInt,
    rd: BigInt,
    enc_b: BigInt,
    pi_b: BigInt,
    y: BigInt,

}