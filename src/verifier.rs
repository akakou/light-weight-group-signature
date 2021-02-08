use crate::signature::GroupSignature;

use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar};
use num_bigint::BigUint;
use sha2::Sha512;

pub struct Verifiyer {
    pub pk_as: EdwardsPoint,
}

impl Verifiyer {
    pub fn new(pk_as: EdwardsPoint) -> Self {
        Self { pk_as }
    }

    pub fn verify(&self, signature: &GroupSignature, msg: &BigUint) -> Result<(), u32> {
        let mut msg_bin = msg.to_bytes_le();
        let mut r_dash_bin = signature.r_dash.compress().to_bytes().to_vec();
        let mut a_bin = signature.a.compress().as_bytes().to_vec();
        let p_bin = signature.p.to_bytes().to_vec();

        // PKmu = R'mu + Ppid * PK
        let pk_mu = signature.r_dash + self.pk_as * signature.p;

        // H = H(P||ts||R||A)
        let mut h_mu = p_bin;
        h_mu.append(&mut msg_bin);
        h_mu.append(&mut r_dash_bin);
        h_mu.append(&mut a_bin);

        let h_mu = Scalar::hash_from_bytes::<Sha512>(&h_mu);

        // VerMU·P = A + PKMU·HMU
        let left = constants::ED25519_BASEPOINT_POINT * signature.ver;
        let right = signature.a + pk_mu * h_mu;

        if right == left {
            Ok(())
        } else {
            Err(0)
        }
    }
}
