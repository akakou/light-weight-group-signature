use crate::member::Member;
use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};

use num_bigint::BigUint;

use k256::{EncodedPoint, NonZeroScalar};
use rand::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct GroupManager {
    pub s: NonZeroScalar,
    pub pk: EncodedPoint,
}

impl GroupManager {
    pub fn random(rng: impl RngCore + CryptoRng) -> Self {
        let s = NonZeroScalar::random(rng);
        let pk = generate_public_key(&s);

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

    pub fn register(&self, rng: impl RngCore + CryptoRng) -> Member {
        let mut id = self.id.to_bytes_le();
        let s = self.gm.s.as_ref();

        // RMU = rMU·P
        let r_sec = NonZeroScalar::random(rng);
        let r_ref = r_sec.as_ref();

        let r_pub = generate_public_key(&r_sec);

        // SMU = rMU + H1(R||ID)·s
        let mut hash = r_pub.as_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut id);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        let s = r_ref + hash * s;
        let s = NonZeroScalar::new(s).unwrap();

        Member {
            id: self.id.clone(),
            r: r_pub,
            s: s,
            pk_as: self.gm.pk,
            pk: None
        }
    }
}
