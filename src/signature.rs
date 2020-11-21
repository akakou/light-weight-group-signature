use k256::{EncodedPoint, NonZeroScalar};

pub struct GroupSignature {
    pub p: NonZeroScalar,
    pub r_dash: EncodedPoint,
    pub a: EncodedPoint,
    pub ver: NonZeroScalar,
}