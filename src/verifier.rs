#![no_std]

use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};
use crate::signature::GroupSignature;

use k256::{EncodedPoint, ProjectivePoint};
use num_bigint::BigUint;

pub struct Verifiyer {
    pub PKas: EncodedPoint,
}

impl Verifiyer {
    pub fn new(PKas: EncodedPoint) -> Self {
        Self {
            PKas: PKas
        }
    }

    pub fn verify(&self, signature: &GroupSignature, msg: &BigUint) -> Result<(), u32> {
        let PKas = self.PKas.decode::<ProjectivePoint>().unwrap();
        let R__dash = signature.R_dash.decode::<ProjectivePoint>().unwrap();
        
        let mut msg_bin = msg.to_bytes_be();
        let mut R_dash_bin = signature.R_dash.as_bytes().to_vec();
        let mut A_bin = signature.A.as_bytes().to_vec();
        let mut P_bin = signature.P.to_bytes().to_vec();

        let A = signature.A.decode::<ProjectivePoint>().unwrap();

        // PKmu = R'mu + Ppid * PK
        let PKmu = R__dash + PKas * &*signature.P;

        // H = H(P||ts||R||A)
        let mut Hmu = P_bin;
        Hmu.append(&mut msg_bin);
        Hmu.append(&mut R_dash_bin);
        Hmu.append(&mut A_bin);

        let Hmu = hash_sha256(&Hmu);
        let Hmu = biguint_to_scalar(&Hmu);

        // VerMU·P = A + PKMU·HMU
        let left = generate_public_key(&signature.Ver)
            .decode::<ProjectivePoint>()
            .unwrap();

        let right = A + PKmu * Hmu;

        if right == left {
            Ok(())
        } else {
            Err((0))
        }
    }
}