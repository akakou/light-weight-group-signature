use k256::{EncodedPoint, NonZeroScalar};

pub struct GroupSignature {
    pub P: NonZeroScalar,
    pub R_dash: EncodedPoint,
    pub A: EncodedPoint,
    pub Ver: NonZeroScalar,
}