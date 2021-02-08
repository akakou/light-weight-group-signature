use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};


pub struct GroupSignature {
    pub p: Scalar,
    pub r_dash: EdwardsPoint,
    pub a: EdwardsPoint,
    pub ver: Scalar,
}