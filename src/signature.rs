use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupSignature {
    pub p: Scalar,
    pub r_dash: EdwardsPoint,
    pub a: EdwardsPoint,
    pub ver: Scalar,
}