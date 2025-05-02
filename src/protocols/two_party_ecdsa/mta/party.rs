use std::cmp;

use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use paillier::Paillier;
use paillier::{Decrypt, EncryptWithChosenRandomness, KeyGeneration};
use paillier::{DecryptionKey, EncryptionKey, Randomness, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zk_paillier::zkproofs::NiCorrectKeyProof;

use super::party_one::PaillierKeyPair;
use super::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMessage;
use super::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMessage;
use super::SECURITY_BITS;

use crate::utilities::mta::MessageB;
use crate::utilities::mta_2021::zkp_p::PiPProof;
use crate::Error;

use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};
use paillier::{DecryptionKey, EncryptionKey, Randomness, RawCiphertext, RawPlaintext};

use crate::utilities::zk_pdl_with_slack::PDLwSlackProof;
use crate::utilities::zk_pdl_with_slack::PDLwSlackStatement;
use crate::utilities::zk_pdl_with_slack::PDLwSlackWitness;

use crate::utilities::mta_2021::{zkp_p, zkp_qr, zkp_qrdl, zkp_range_proof};

pub struct MtAParty {
    pub n: BigInt,
    phi_n: BigInt,
    pub g: BigInt,
    pub h: BigInt,

    pub pip_proof: zkp_p::PiPProof,
    pub qr_proof: zkp_qr::QRProof,
    pub qrdl_proof: zkp_qrdl::QRdlProof,
    pub range_proof: zkp_range_proof::RPwRProof,
}

impl MtAParty {
    pub fn mta_setup(paillier_key: PaillierKeyPair, g: BigInt, h: BigInt) -> Self{
        let n = paillier_key.ek.n.clone();
        let phi_n = paillier_key.dk.p.clone()
        let pip_proof = paillier_key.generate_pip_proof();


        MtAParty { n, phi_n, g, h, pip_proof, qr_proof, qrdl_proof, range_proof }
    }
}