use crate::signature::GroupSignature;
use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};

use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub struct Member {
    pub id: BigUint,
    pub r: EncodedPoint,
    pub s: NonZeroScalar,
    pub pid: BigUint,
    pub pwv: NonZeroScalar,
    pub pk_as: EncodedPoint,
    pub pk: Option<EncodedPoint>,
}

impl Member {
    pub fn setup(&mut self) -> Result<(), u32> {
        let mut pid_bin = self.pid.to_bytes_be();
        let pk_as = self.pk_as.decode::<ProjectivePoint>().unwrap();
        let r = self.r.decode::<ProjectivePoint>().unwrap();

        // left
        let left = generate_public_key(&self.s);
        let left = left.decode::<ProjectivePoint>().unwrap();

        // right
        // SMU = rMU + H1(PIDMU‖RMU)·s
        let mut hash = self.r.as_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut pid_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);
        let hash = NonZeroScalar::new(hash).unwrap();

        let right = r + pk_as * &*hash;

        let pk: EncodedPoint = right.to_affine().into();
        self.pk = Some(pk);

        if left == right {
            Ok(())
        }else{
            Err(1)
        }
   }

    pub fn sign(
        &mut self,
        msg: &BigUint,
        rng1: impl CryptoRng + RngCore,
        rng2: impl CryptoRng + RngCore,
    ) -> GroupSignature {
        let mut pid_bin = self.pid.to_bytes_be();
        let r_bin = self.r.as_bytes().to_vec();
        let mut msg_bin = msg.to_bytes_be();
        let r_dash = self.r.decode::<ProjectivePoint>().unwrap();

        // A = a·P
        let a_sec = NonZeroScalar::random(rng1);
        let a_pub = generate_public_key(&a_sec);
        let mut a_bin = a_pub.as_bytes().to_vec();

        // c
        let c = NonZeroScalar::random(rng2);

        // Ppid = c·H1(PIDMU‖RMU),
        let mut hash = r_bin.clone();
        hash.push(00 as u8);
        hash.append(&mut pid_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        let p = c.as_ref() * &hash;
        let p = NonZeroScalar::new(p).unwrap();
        let p_bin = p.to_bytes().to_vec();

        // R' = c·R
        let r_dash = r_dash * c.as_ref();
        let r_dash: EncodedPoint = r_dash.to_affine().into();
        let mut r_dash_bin = r_dash.as_bytes().to_vec();

        // S' = c·S
        let s_dash = self.s.as_ref() * c.as_ref();

        // H = H(P||msg||R'||A)
        let mut hash = p_bin;
        hash.append(&mut msg_bin);
        hash.append(&mut r_dash_bin);
        hash.append(&mut a_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        // Ver = a + S'·H
        let ver = a_sec.as_ref() + s_dash * hash;
        let ver = NonZeroScalar::new(ver).unwrap();

        GroupSignature {
            p: p,
            r_dash: r_dash,
            a: a_pub,
            ver: ver,
        }
    }
}
