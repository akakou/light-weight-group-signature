use crate::member::Member;

use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

extern crate sha2;
use sha2::Sha512;

#[derive(Clone)]
pub struct GroupManager {
    pub s: Scalar,
    pub pk: EdwardsPoint,
}

impl GroupManager {
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let s = Scalar::random(rng);
        let pk = constants::ED25519_BASEPOINT_POINT * s;

        Self { s: s, pk: pk }
    }

    pub fn register_member(
        &self,
        id: BigUint,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Member {
        let register = MemberRegister::random(self.clone(), id);
        register.register(rng)
    }
}

pub struct MemberRegister {
    id: BigUint,
    gm: GroupManager,
}

impl MemberRegister {
    pub fn random(
        gm: GroupManager,
        id: BigUint,
    ) -> Self {
        Self {
            id: id,
            gm: gm,
        }
    }

    pub fn register(&self, rng: &mut (impl RngCore + CryptoRng)) -> Member {
        let mut id = self.id.to_bytes_le().to_vec();

        // RMU = rMU·P
        let r_sec = Scalar::random(rng);
        let r_pub = constants::ED25519_BASEPOINT_POINT * r_sec;

        // SMU = rMU + H1(R||ID)·s
        let mut hash = r_pub.compress().to_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut id);

        let hash = Scalar::hash_from_bytes::<Sha512>(&hash);

        let s_pub = r_sec + hash * self.gm.s;

        Member {
            id: self.id.clone(),
            r: r_pub,
            s: s_pub,
            pk_as: self.gm.pk,
            pk: None
        }
    }
}
