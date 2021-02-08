use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};
use crate::signature::GroupSignature;

use k256::{EncodedPoint, ProjectivePoint};
use num_bigint::BigUint;

pub struct Verifiyer {
    pub pk_as: EncodedPoint,
}

impl Verifiyer {
    pub fn new(pk_as: EncodedPoint) -> Self {
        Self {
            pk_as: pk_as
        }
    }

    pub fn verify(&self, signature: &GroupSignature, msg: &BigUint) -> Result<(), u32> {
        let pk_as = self.pk_as.decode::<ProjectivePoint>().unwrap();
        let r_dash = signature.r_dash.decode::<ProjectivePoint>().unwrap();
        
        let mut msg_bin = msg.to_bytes_le();
        let mut r_dash_bin = signature.r_dash.as_bytes().to_vec();
        let mut a_bin = signature.a.as_bytes().to_vec();
        let p_bin = signature.p.to_bytes().to_vec();

        let a = signature.a.decode::<ProjectivePoint>().unwrap();

        // PKmu = R'mu + Ppid * PK
        let pk_mu = r_dash + pk_as * &*signature.p;

        // H = H(P||ts||R||A)
        let mut h_mu = p_bin;
        h_mu.append(&mut msg_bin);
        h_mu.append(&mut r_dash_bin);
        h_mu.append(&mut a_bin);

        let h_mu = hash_sha256(&h_mu);
        let h_mu = biguint_to_scalar(&h_mu);

        // VerMU·P = A + PKMU·HMU
        let left = generate_public_key(&signature.ver)
            .decode::<ProjectivePoint>()
            .unwrap();

        let right = a + pk_mu * h_mu;

        if right == left {
            Ok(())
        } else {
            Err(0)
        }
    }
}
