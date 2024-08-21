use patching_wwlp::{gen_all_auto_keys, generate_scheme_switching_key, get_glwe_l2_err, get_glwe_max_err, switch_scheme, trace_assign, FftType};
use tfhe::core_crypto::{
    prelude::*,
    fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListView,
};

type Scalar = u64;

fn main() {
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);

    let ss_base_log = DecompositionBaseLog(6);
    let ss_level = DecompositionLevelCount(8);

    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(3);

    let auto_base_log = DecompositionBaseLog(5);
    let auto_level = DecompositionLevelCount(11);

    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();


    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(glwe_dimension, polynomial_size, &mut secret_generator);
    let glwe_size = glwe_dimension.to_glwe_size();

    let ss_key = generate_scheme_switching_key(
        &glwe_sk,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let ss_key = ss_key.as_view();

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        FftType::Split16,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let correct_val_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));


    println!("-------- GLWE input with zero error ---------");
    let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    for mut glwe in glev.iter_mut() {
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut glwe,
            &PlaintextList::from_container((0..polynomial_size.0).map(|_| Scalar::ZERO).collect::<Vec<Scalar>>()),
            StandardDev(0.0),
            &mut encryption_generator,
        );
    }

    test_scheme_switching_err(&glwe_sk, &glev, ggsw_base_log, ggsw_level, ss_key, &correct_val_list, &correct_val_list);


    println!("\n\n-------- GLWE input ---------");
    let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    for mut glwe in glev.iter_mut() {
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut glwe,
            &PlaintextList::from_container((0..polynomial_size.0).map(|_| Scalar::ZERO).collect::<Vec<Scalar>>()),
            StandardDev(0.0),
            &mut encryption_generator,
        );

        for val in glwe.get_mut_body().as_mut().iter_mut() {
            *val += Scalar::ONE << 40;
        }
    }

    test_scheme_switching_err(&glwe_sk, &glev, ggsw_base_log, ggsw_level, ss_key, &correct_val_list, &correct_val_list);


    println!("\n\n-------- GLWE input with a large error only on the constant --------");
    let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    for mut glwe in glev.iter_mut() {
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut glwe,
            &PlaintextList::from_container((0..polynomial_size.0).map(|_| Scalar::ZERO).collect::<Vec<Scalar>>()),
            StandardDev(0.0),
            &mut encryption_generator,
        );

        for (i, val) in glwe.get_mut_body().as_mut().iter_mut().enumerate() {
            if i == 0 {
                *val += Scalar::ONE << 50;
            } else {
                *val += Scalar::ONE << 40;
            }
        }
    }

    test_scheme_switching_err(&glwe_sk, &glev, ggsw_base_log, ggsw_level, ss_key, &correct_val_list, &correct_val_list);

    println!("\n\n-------- GLWE input with trace error --------");
    let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    for mut glwe in glev.iter_mut() {
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut glwe,
            &PlaintextList::from_container((0..polynomial_size.0).map(|_| Scalar::ZERO).collect::<Vec<Scalar>>()),
            StandardDev(0.0),
            &mut encryption_generator,
        );

        trace_assign(&mut glwe, &auto_keys);
    }

    test_scheme_switching_err(&glwe_sk, &glev, ggsw_base_log, ggsw_level, ss_key, &correct_val_list, &correct_val_list);
}

fn test_scheme_switching_err<KeyCont, InputCont, BeforeCont, AfterCont>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    glev: &GlweCiphertextList<InputCont>,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    ss_key: FourierGgswCiphertextListView,
    correct_val_before: &PlaintextList<BeforeCont>,
    correct_val_after: &PlaintextList<AfterCont>,
) where
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    BeforeCont: Container<Element = Scalar>,
    AfterCont: Container<Element = Scalar>,
{
    println!("GLEV error");
    for (k, glwe) in glev.iter().enumerate() {
        let max_err = get_glwe_max_err(
            &glwe_secret_key,
            &glwe,
            &correct_val_before,
        );
        let l2_err = get_glwe_l2_err(
            &glwe_secret_key,
            &glwe,
            &correct_val_before,
        );

        println!("[{}] (l2) {:.2} bits | (Max) {:.2} bits", k, l2_err.log2(), (max_err as f64).log2());
    }
    println!();

    let glwe_size = glev.glwe_size();
    let polynomial_size = glev.polynomial_size();
    let ciphertext_modulus = glev.ciphertext_modulus();

    // Scheme switching
    let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);
    switch_scheme(&glev, &mut ggsw, ss_key);

    println!("GGSW error after scheme switching");
    for (idx, ggsw_row_mat) in ggsw.iter().enumerate() {
        println!("Row[{idx}]");
        for (k, glwe) in ggsw_row_mat.as_glwe_list().iter().enumerate() {
            let max_err = get_glwe_max_err(
                &glwe_secret_key,
                &glwe,
                &correct_val_after,
            );
            let l2_err = get_glwe_l2_err(
                &glwe_secret_key,
                &glwe,
                &correct_val_after,
            );

            println!("       GLWE[{}] (l2) {:.2} bits | (Max) {:.2} bits", k, l2_err.log2(), (max_err as f64).log2());
        }
    }
}
