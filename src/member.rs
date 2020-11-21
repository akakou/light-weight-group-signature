use crate::signature::GroupSignature;

use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};

use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub struct Member {
    pub id: BigUint,
    pub R: EncodedPoint,
    pub S: NonZeroScalar,
    pub PID: BigUint,
    pub PWV: NonZeroScalar,
    pub PKas: EncodedPoint,
    pub PK: Option<EncodedPoint>,
}

impl Member {
    pub fn setup(&mut self) -> Result<(), u32> {
        let mut PID_bin = self.PID.to_bytes_be();
        let PKas = self.PKas.decode::<ProjectivePoint>().unwrap();
        let R = self.R.decode::<ProjectivePoint>().unwrap();

        // left
        let left = generate_public_key(&self.S);
        let left = left.decode::<ProjectivePoint>().unwrap();

        // right
        // SMU = rMU + H1(PIDMU‖RMU)·s
        let mut hash = self.R.as_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut PID_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);
        let hash = NonZeroScalar::new(hash).unwrap();

        let right = R + PKas * &*hash;

        let PK: EncodedPoint = right.to_affine().into();
        self.PK = Some(PK);

        if left == right {
            Ok(())
        }else{
            Err(1)
        }
   }

    pub fn sign(
        &mut self,
        msg: &BigUint,
        rng1: &mut (impl CryptoRng + RngCore),
        rng2: &mut (impl CryptoRng + RngCore),
    ) -> GroupSignature {
        let mut PID_bin = self.PID.to_bytes_be();
        let mut R_bin = self.R.as_bytes().to_vec();
        let mut ts_bin = msg.to_bytes_be();
        let R_dash = self.R.decode::<ProjectivePoint>().unwrap();

        // A = a·P
        let a = NonZeroScalar::random(rng1);
        let A = generate_public_key(&a);
        let mut A_bin = A.as_bytes().to_vec();

        // c
        let c = NonZeroScalar::random(rng2);

        // Ppid = c·H1(PIDMU‖RMU),
        let mut hash = R_bin.clone();
        hash.push(00 as u8);
        hash.append(&mut PID_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        let P = c.as_ref() * &hash;
        let P = NonZeroScalar::new(P).unwrap();
        let mut P_bin = P.to_bytes().to_vec();

        // R' = c·R
        let R_dash = R_dash * c.as_ref();
        let R_dash: EncodedPoint = R_dash.to_affine().into();
        let mut R_dash_bin = R_dash.as_bytes().to_vec();

        // S' = c·S
        let S_dash = self.S.as_ref() * c.as_ref();

        // H = H(P||msg||R'||A)
        let mut H = P_bin;
        H.append(&mut ts_bin);
        H.append(&mut R_dash_bin);
        H.append(&mut A_bin);

        let H = hash_sha256(&H);
        let H = biguint_to_scalar(&H);

        // Ver = a + S'·H
        let Ver = a.as_ref() + S_dash * H;
        let Ver = NonZeroScalar::new(Ver).unwrap();

        GroupSignature {
            P: P,
            R_dash: R_dash,
            A: A,
            Ver: Ver,
        }
    }
}