#![no_std]
use crate::member::Member;
use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};

use num_bigint::BigUint;

use k256::{EncodedPoint, NonZeroScalar};
use rand::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct GroupManager {
    pub s: NonZeroScalar,
    pub PK: EncodedPoint,
}

impl GroupManager {
    pub fn random(rng: impl RngCore + CryptoRng) -> Self {
        let s = NonZeroScalar::random(rng);
        let PK = generate_public_key(&s);

        Self { s: s, PK: PK }
    }

    pub fn register_member(
        &self,
        id: BigUint,
        h: BigUint,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Member {
        let register = MemberRegister::random(self.clone(), id, h, rng);
        register.register(rng)
    }
}

pub struct MemberRegister {
    id: BigUint,
    h: BigUint,
    r: NonZeroScalar,
    gm: GroupManager,
}

impl MemberRegister {
    pub fn random(
        gm: GroupManager,
        id: BigUint,
        h: BigUint,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Self {
        Self {
            id: id,
            h: h,
            gm: gm,
            r: NonZeroScalar::random(rng),
        }
    }

    pub fn register(&self, rng: &mut (impl CryptoRng + RngCore)) -> Member {
        let s = self.gm.s.as_ref();

        let mut PK_bin = self.gm.PK.as_bytes().to_vec();

        // RMU = rMU·P
        let r = NonZeroScalar::random(rng);
        let r_ref = r.as_ref();

        let R = generate_public_key(&r);
        let R_bin = R.as_bytes().to_vec();

        // PIDMU = IDMU⊕H3(rMU‖PK)
        let mut hash = R_bin.clone();
        hash.push(00 as u8);
        hash.append(&mut PK_bin);

        let hash = hash_sha256(&hash);

        let PID = self.id.clone() ^ hash.clone();
        let mut PID_bin = PID.to_bytes_be();

        // SMU = rMU + H1(PIDMU‖RMU)·s
        let mut hash = R.as_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut PID_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        let S = r_ref + hash * s;
        let S = NonZeroScalar::new(S).unwrap();

        let S_bin = S.as_ref();
        let mut S_bin = S_bin.to_bytes().to_vec();

        // PWVMU = H1(H1(IDMU‖PWMU)‖SMU)
        let mut hash = self.h.to_bytes_le();
        hash.push(00 as u8);
        hash.append(&mut S_bin);

        let hash = hash_sha256(&S_bin);

        let PWV = biguint_to_scalar(&hash);
        let PWV = NonZeroScalar::new(PWV).unwrap();

        Member {
            id: self.id.clone(),
            R: R,
            S: S,
            PID: PID,
            PWV: PWV,
            PKas: self.gm.PK,
            PK: None
        }
    }
}
