use crate::signature::GroupSignature;

use num_bigint::BigUint;
use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar};
use rand::{CryptoRng, RngCore};
use sha2::Sha512;

pub struct Member {
    pub id: BigUint,
    pub r: EdwardsPoint,
    pub s: Scalar,
    pub pk_as: EdwardsPoint,
    pub pk: Option<EdwardsPoint>,
}

impl Member {
    pub fn setup(&mut self) -> Result<(), u32> {
        // SMU = rMU + H1(RMU||ID)·s
        let mut hash = self.r.compress().to_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut self.id.to_bytes_le());

        let hash = Scalar::hash_from_bytes::<Sha512>(&hash);

        let pk = self.r + self.pk_as * hash;
        self.pk = Some(pk);

        // checker
        // checker = P * SMU
        let checker = constants::ED25519_BASEPOINT_POINT * self.s;

        if pk == checker {
            Ok(())
        }else{
            Err(1)
        }
   }

    pub fn sign(
        &mut self,
        msg: &BigUint,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> GroupSignature {
        let mut id = self.id.to_bytes_le();
        let mut msg_bin = msg.to_bytes_le();

        // A = a·P
        let a_sec = Scalar::random(rng);
        let a_pub = constants::ED25519_BASEPOINT_POINT * a_sec;
        let mut a_bin = a_pub.compress().to_bytes().to_vec();

        // c
        let c = Scalar::random(rng);

        // Ppid = c·H1(PIDMU‖RMU),
        let mut hash = self.r.compress().to_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut id);

        let hash = Scalar::hash_from_bytes::<Sha512>(&hash);


        let p = c * hash;
        let p_bin = p.to_bytes().to_vec();

        // R' = c·R
        let r_dash = self.r * c;
        let mut r_dash_bin = r_dash.compress().to_bytes().to_vec();

        // S' = c·S
        let s_dash = self.s * c;

        // H = H(P||msg||R'||A)
        let mut hash = p_bin;
        hash.append(&mut msg_bin);
        hash.append(&mut r_dash_bin);
        hash.append(&mut a_bin);

        let hash = Scalar::hash_from_bytes::<Sha512>(&hash);

        // Ver = a + S'·H
        let ver = a_sec + s_dash * hash;

        GroupSignature {
            p: p,
            r_dash: r_dash,
            a: a_pub,
            ver: ver,
        }
    }
}
