#![no_std]

use crate::gm::GroupManager;
use crate::member::Member;
use crate::verifier::Verifiyer;

use k256::{NonZeroScalar, Scalar};
use num_bigint::BigUint;
use rand_core::SeedableRng;

#[test]
fn test_auth() {
    let id = BigUint::from(10 as u32);
    let h = BigUint::from(10 as u32);
    let msg = BigUint::from(10 as u32);
    let no_msg = BigUint::from(11 as u32);

    let mut rng = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng1 = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng2 = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng3 = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng4 = rand::rngs::StdRng::from_seed([0; 32]);

    let gm = GroupManager::random(rng);

    let mut member = gm.register_member(id, h, &mut rng2);
    member.setup();

    let signature = member.sign(&msg, &mut rng2, &mut rng3);
    
    let verifier = Verifiyer::new(gm.PK);
    verifier.verify(&signature, &msg).unwrap();

    match verifier.verify(&signature, &no_msg) {
        Ok(_) => { assert!(false); }
        Err(_) => { assert!(true); }
    }
}
