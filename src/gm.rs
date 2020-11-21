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
        h: BigUint,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Member {
        let register = MemberRegister::random(self.clone(), id, h);
        register.register(rng)
    }
}

pub struct MemberRegister {
    id: BigUint,
    h: BigUint,
    gm: GroupManager,
}

impl MemberRegister {
    pub fn random(
        gm: GroupManager,
        id: BigUint,
        h: BigUint,
    ) -> Self {
        Self {
            id: id,
            h: h,
            gm: gm,
        }
    }

    pub fn register(&self, rng: impl RngCore + CryptoRng) -> Member {
        let s = self.gm.s.as_ref();

        let mut pk_bin = self.gm.pk.as_bytes().to_vec();

        // RMU = rMU·P
        let r_sec = NonZeroScalar::random(rng);
        let r_ref = r_sec.as_ref();

        let r_pub = generate_public_key(&r_sec);
        let r_bin = r_pub.as_bytes().to_vec();

        // PIDMU = IDMU⊕H3(rMU‖PK)
        let mut hash = r_bin.clone();
        hash.push(00 as u8);
        hash.append(&mut pk_bin);

        let hash = hash_sha256(&hash);

        let pid = self.id.clone() ^ hash.clone();
        let mut pid_bin = pid.to_bytes_be();

        // SMU = rMU + H1(PIDMU‖RMU)·s
        let mut hash = r_pub.as_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut pid_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        let s = r_ref + hash * s;
        let s = NonZeroScalar::new(s).unwrap();

        let s_bin = s.as_ref();
        let mut s_bin = s_bin.to_bytes().to_vec();

        // PWVMU = H1(H1(IDMU‖PWMU)‖SMU)
        let mut hash = self.h.to_bytes_le();
        hash.push(00 as u8);
        hash.append(&mut s_bin);

        let hash = hash_sha256(&s_bin);

        let pwv = biguint_to_scalar(&hash);
        let pwv = NonZeroScalar::new(pwv).unwrap();

        Member {
            id: self.id.clone(),
            r: r_pub,
            s: s,
            pid: pid,
            pwv: pwv,
            pk_as: self.gm.pk,
            pk: None
        }
    }
}
