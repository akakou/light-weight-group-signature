#[test]
fn test_auth() {
    use crate::gm::GroupManager;
    use crate::verifier::Verifiyer;

    use num_bigint::BigUint;
    use rand_core::SeedableRng;

    let id = BigUint::from(10 as u32);
    let h = BigUint::from(10 as u32);
    let msg = BigUint::from(10 as u32);
    let no_msg = BigUint::from(11 as u32);

    let rng = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng1 = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng2 = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng3 = rand::rngs::StdRng::from_seed([0; 32]);

    let gm = GroupManager::random(rng);

    let mut member = gm.register_member(id, h, &mut rng1);
    member.setup().unwrap();

    let signature = member.sign(&msg, &mut rng2, &mut rng3);
    
    let verifier = Verifiyer::new(gm.pk);
    verifier.verify(&signature, &msg).unwrap();

    match verifier.verify(&signature, &no_msg) {
        Ok(_) => { assert!(false); }
        Err(_) => { assert!(true); }
    }
}