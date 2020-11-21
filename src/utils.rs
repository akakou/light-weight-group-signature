#![no_std]
use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint, Scalar};

use num_bigint::{BigUint, ToBigUint};
use num_traits::cast::ToPrimitive;

use elliptic_curve::ff::PrimeField;
use sha2::{Digest, Sha256};

pub fn generate_public_key(secret_key: &NonZeroScalar) -> EncodedPoint {
    (ProjectivePoint::generator() * &**secret_key)
        .to_affine()
        .into()
}

pub fn hash_sha256(binary: &[u8]) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(binary);
    let hash = &hasher.finalize();

    BigUint::from_bytes_le(&hash.to_vec())
}

pub fn biguint_to_scalar(x: &BigUint) -> Scalar {
    let bytes = biguint_to_bytes(x);
    Scalar::from_repr(bytes.into()).unwrap()
}

pub fn scalar_to_biguint(scalar: &Scalar) -> Option<BigUint> {
    Some(bytes_to_biguint(scalar.to_bytes().as_ref()))
}

pub fn bytes_to_biguint(bytes: &[u8; 32]) -> BigUint {
    bytes
        .iter()
        .enumerate()
        .map(|(i, w)| w.to_biguint().unwrap() << ((31 - i) * 8))
        .sum()
}

fn biguint_to_bytes(x: &BigUint) -> [u8; 32] {
    let mask = BigUint::from(u8::MAX);
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = ((x >> ((31 - i) * 8)) as BigUint & &mask).to_u8().unwrap();
    }
    bytes
}


#[test]
fn test_hash_sha256() {
    use hex_literal::hex;

    let result = hash_sha256(b"hello world");

    assert_eq!(
        result,
        BigUint::from_bytes_le(
            &hex!(
                "
    b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
"
            )
            .to_vec()
        )
    );
}
