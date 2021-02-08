use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GroupSignature {
    pub p: Scalar,
    pub r_dash: EdwardsPoint,
    pub a: EdwardsPoint,
    pub ver: Scalar,
}
