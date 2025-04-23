// MtA in CCS+21 figure 7
// Paillier based MtA

use crate::utilities::mta_2021::zkp_p::*;
use crate::utilities::mta_2021::zkp_qr::*;
use crate::utilities::mta_2021::zkp_qrdl::*; // dlog_statement
use crate::utilities::mta_2021::zkp_rang_proofs::*;
use crate::utilities::mta_2021::zkp_affran::*;
use crate::utilities::mta_2021::{MessageA, MessageB};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};

#[test]
fn test_mta_2021() {
    let party_one_input =BigInt::sample_below(q); // a( = x1' )
    // let (n, zkp_p, zkp_qr, zkp_qrdl) = ;
    let party_two_input = BigInt::sample_below(q); // b( = k2 )
    // let (n0, zkp_p0, zkp_qr0, zkp_qrdl0) = ;
    let p1 = PartyOne::new();
    let p2 = PartyTwo::new();

    let (c_b, zkp_b) = ;
    let (c_a, zkp_a) = ;
    
    // let (m_a, _) = MessageA::a(&party_one_input, &ek_party_one, &[dlog_statement.clone()]);
    // let (m_b, beta, _, _) = MessageB::b(&party_two_input, &ek_party_one, m_a, &[dlog_statement]).unwrap();
    // let alpha = m_b
        // .verify_proofs_get_alpha(&dk_party_one, &party_one_input)
        // .expect("wrong dlog or m_b");

     // alpha + beta = a * b (MtA)
     // tA + tB = x1' * k2 (2021)
    let left = alpha.0 + beta;
    let right = party_one_input * party_two_input;
    assert_eq!(left, right);
}
