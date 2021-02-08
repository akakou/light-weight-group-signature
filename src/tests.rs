#[test]
fn test_auth() {
    use crate::gm::GroupManager;
    use crate::verifier::Verifiyer;

    use num_bigint::BigUint;
    use rand_core::SeedableRng;

    let id = BigUint::from(10 as u32);
    let msg = BigUint::from(10 as u32);
    let no_msg = BigUint::from(11 as u32);

    let mut rng = rand::rngs::StdRng::from_seed([0; 32]);

    let gm = GroupManager::random(&mut rng);

    let mut member = gm.register_member(id, &mut rng);
    member.setup().unwrap();

    let signature = member.sign(&msg, &mut rng);

    let verifier = Verifiyer::new(gm.pk);
    verifier.verify(&signature, &msg).unwrap();

    match verifier.verify(&signature, &no_msg) {
        Ok(_) => {
            assert!(false);
        }
        Err(_) => {
            assert!(true);
        }
    }
}
