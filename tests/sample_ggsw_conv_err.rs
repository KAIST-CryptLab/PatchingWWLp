use patching_wwlp::{allocate_and_generate_new_glwe_keyswitch_key, convert_lwe_to_glwe_by_trace_with_preprocessing, convert_lwe_to_glwe_by_trace_with_preprocessing_high_prec, convert_standard_glwe_keyswitch_key_to_fourier, gen_all_auto_keys, generate_scheme_switching_key, get_glwe_l2_err, get_glwe_max_err, switch_scheme, wwlp_cbs_instance::*, FftType, FourierGlweKeyswitchKey};
use rand::Rng;
use tfhe::core_crypto::prelude::*;

type Scalar = u64;
const NUM_REPEAT: usize = 1000;

fn main() {
    /* Lev to GGSW by trace and scheme switching */
    // wopbs_2_2
    let param = *WWLP_CBS_WOPBS_2_2;
    let glwe_dimension = param.glwe_dimension();
    let polynomial_size = param.polynomial_size();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type_auto = param.fft_type_auto();
    let ss_base_log = param.ss_base_log();
    let ss_level = param.ss_level();
    let ggsw_base_log = param.cbs_base_log();
    let ggsw_level = param.cbs_level();

    sample_ggsw_conv_err_by_trace_and_ss(glwe_dimension, polynomial_size, glwe_modular_std_dev, auto_base_log, auto_level, fft_type_auto, ss_base_log, ss_level, ggsw_base_log, ggsw_level, NUM_REPEAT);

    // wopbs_3_3 & wopbs_4_4
    let param = *HIGHPREC_WWLP_CBS_WOPBS_3_3;
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let ggsw_base_log = param.cbs_base_log();
    let ggsw_level = param.cbs_level();

    let large_glwe_dimension = param.large_glwe_dimension();
    let large_glwe_modular_std_dev = param.large_glwe_modular_std_dev();
    let ds_to_large_base_log = param.glwe_ds_to_large_base_log();
    let ds_to_large_level = param.glwe_ds_to_large_level();
    let fft_type_to_large = param.fft_type_to_large();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type_auto = param.fft_type_auto();
    let ds_from_large_base_log = param.glwe_ds_from_large_base_log();
    let ds_from_large_level = param.glwe_ds_from_large_level();
    let fft_type_from_large = param.fft_type_from_large();
    let ss_base_log = param.ss_base_log();
    let ss_level = param.ss_level();

    sample_ggsw_conv_err_by_high_prec_trace_and_ss(glwe_dimension, large_glwe_dimension, polynomial_size, glwe_modular_std_dev, large_glwe_modular_std_dev, ds_to_large_base_log, ds_to_large_level, fft_type_to_large, auto_base_log, auto_level, fft_type_auto, ds_from_large_base_log, ds_from_large_level, fft_type_from_large, ss_base_log, ss_level, ggsw_base_log, ggsw_level, NUM_REPEAT);

    /* Lev to GGSW by pfks */
    // wopbs_2_2
    let param = *CBS_WOPBS_2_2;
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pfks_base_log = param.pfks_base_log();
    let pfks_level = param.pfks_level();

    sample_ggsw_conv_err_by_pfks(glwe_dimension, polynomial_size, glwe_modular_std_dev, pfks_base_log, pfks_level, NUM_REPEAT);

    // wopbs_message_3_carry_3_ks_pbs and wopbs_message_4_carry_4_ks_pbs
    // wopbs_3_3 & wopbs_4_4
    let param = *CBS_WOPBS_3_3;
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pfks_base_log = param.pfks_base_log();
    let pfks_level = param.pfks_level();

    sample_ggsw_conv_err_by_pfks(glwe_dimension, polynomial_size, glwe_modular_std_dev, pfks_base_log, pfks_level, NUM_REPEAT);
}

#[allow(unused)]
fn sample_ggsw_conv_err_by_trace_and_ss(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: StandardDev,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    fft_type_auto: FftType,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    num_repeat: usize,
) {
    println!("GGSW conversion by trace and ss");
    println!(
        "N: {}, k: {}, B_auto: 2^{}, l_auto: {}, fft_type_auto: {:?}, B_ss: 2^{}, l_ss: {}",
        polynomial_size.0, glwe_dimension.0, auto_base_log.0, auto_level.0, fft_type_auto, ss_base_log.0, ss_level.0
    );

    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();
    let lwe_size = lwe_sk.lwe_dimension().to_lwe_size();

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type_auto,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let ss_key = generate_scheme_switching_key(
        &glwe_sk,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let ss_key = ss_key.as_view();

    let mut rng = rand::thread_rng();

    let mut glev_l_infty_err_list = vec![];
    let mut glev_l2_err_list = vec![];
    let mut ggsw_l_infty_err_list = vec![];
    let mut ggsw_l2_err_list = vec![];

    let glwe_sk_poly_list = glwe_sk.as_polynomial_list();
    let glwe_sk_poly = glwe_sk_poly_list.get(0);

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..2) as Scalar;

        let mut lev = LweCiphertextList::new(Scalar::ZERO, lwe_size, LweCiphertextCount(ggsw_level.0), ciphertext_modulus);

        for (k, mut lwe) in lev.iter_mut().enumerate() {
            let level = k + 1;
            let log_scale = Scalar::BITS as usize - level * ggsw_base_log.0;

            encrypt_lwe_ciphertext(&lwe_sk, &mut lwe, Plaintext(msg << log_scale), StandardDev(0.0), &mut encryption_generator);
        }

        let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);

        for (lwe, mut glwe) in lev.iter().zip(glev.iter_mut()) {
            convert_lwe_to_glwe_by_trace_with_preprocessing(&lwe, &mut glwe, &auto_keys);
        }

        let glwe = glev.get(0);
        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if i == 0 {(msg << (Scalar::BITS as usize - ggsw_base_log.0))} else {Scalar::ZERO}
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &glwe, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &glwe, &correct_val_list);

        glev_l_infty_err_list.push(max_err);
        glev_l2_err_list.push(l2_err);

        let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);
        switch_scheme(&glev, &mut ggsw, ss_key);

        let glwe_list = ggsw.as_glwe_list();
        let output = glwe_list.get(0);

        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if msg == 0 {
                Scalar::ZERO
            } else {
                let glwe_sk_val = *glwe_sk_poly.as_ref().get(i).unwrap();
                glwe_sk_val.wrapping_neg() << (Scalar::BITS as usize - ggsw_base_log.0)
            }
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &output, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &output, &correct_val_list);

        ggsw_l_infty_err_list.push(max_err);
        ggsw_l2_err_list.push(l2_err);
    }

    println!("Lev -> GLev by Trace");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in glev_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in glev_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());

    println!("GLev -> GGSW by Scheme Switching");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in ggsw_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in ggsw_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}


#[allow(unused)]
fn sample_ggsw_conv_err_by_high_prec_trace_and_ss(
    glwe_dimension: GlweDimension,
    large_glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: StandardDev,
    large_glwe_modular_std_dev: StandardDev,
    ds_to_large_base_log: DecompositionBaseLog,
    ds_to_large_level: DecompositionLevelCount,
    fft_type_to_large: FftType,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    fft_type_auto: FftType,
    ds_from_large_base_log: DecompositionBaseLog,
    ds_from_large_level: DecompositionLevelCount,
    fft_type_from_large: FftType,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    num_repeat: usize,
) {
    println!("GGSW conversion by high prec trace and ss");
    println!(
"N: {}, k: {}, k': {},
B_to_k': 2^{}, l_to_k': {}, fft_type_to_k': {:?},
B_auto: 2^{}, l_auto: {}, fft_type_auto: {:?},
B_to_k: 2^{}, l_to_k: {}, fft_type_to_k: {:?},
B_ss: 2^{}, l_ss: {}",
        polynomial_size.0, glwe_dimension.0, large_glwe_dimension.0,
        ds_to_large_base_log.0, ds_to_large_level.0, fft_type_to_large,
        auto_base_log.0, auto_level.0, fft_type_auto,
        ds_from_large_base_log.0, ds_from_large_level.0, fft_type_from_large,
        ss_base_log.0, ss_level.0
    );

    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();
    let lwe_size = lwe_sk.lwe_dimension().to_lwe_size();

    let large_glwe_sk = GlweSecretKey::generate_new_binary(large_glwe_dimension, polynomial_size, &mut secret_generator);
    let large_glwe_size = large_glwe_dimension.to_glwe_size();

    let glwe_dsk_to_large = allocate_and_generate_new_glwe_keyswitch_key(
        &glwe_sk,
        &large_glwe_sk,
        ds_to_large_base_log,
        ds_to_large_level,
        large_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_dsk_to_large = FourierGlweKeyswitchKey::new(
        glwe_size,
        large_glwe_size,
        polynomial_size,
        ds_to_large_base_log,
        ds_to_large_level,
        fft_type_to_large,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&glwe_dsk_to_large, &mut fourier_glwe_dsk_to_large);

    let glwe_dsk_from_large = allocate_and_generate_new_glwe_keyswitch_key(
        &large_glwe_sk,
        &glwe_sk,
        ds_from_large_base_log,
        ds_from_large_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_dsk_from_large = FourierGlweKeyswitchKey::new(
        large_glwe_size,
        glwe_size,
        polynomial_size,
        ds_from_large_base_log,
        ds_from_large_level,
        fft_type_from_large,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&glwe_dsk_from_large, &mut fourier_glwe_dsk_from_large);

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type_auto,
        &large_glwe_sk,
        large_glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let ss_key = generate_scheme_switching_key(
        &glwe_sk,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let ss_key = ss_key.as_view();

    let mut rng = rand::thread_rng();

    let mut glev_l_infty_err_list = vec![];
    let mut glev_l2_err_list = vec![];
    let mut ggsw_l_infty_err_list = vec![];
    let mut ggsw_l2_err_list = vec![];

    let glwe_sk_poly_list = glwe_sk.as_polynomial_list();
    let glwe_sk_poly = glwe_sk_poly_list.get(0);

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..2) as Scalar;

        let mut lev = LweCiphertextList::new(Scalar::ZERO, lwe_size, LweCiphertextCount(ggsw_level.0), ciphertext_modulus);

        for (k, mut lwe) in lev.iter_mut().enumerate() {
            let level = k + 1;
            let log_scale = Scalar::BITS as usize - level * ggsw_base_log.0;

            encrypt_lwe_ciphertext(&lwe_sk, &mut lwe, Plaintext(msg << log_scale), StandardDev(0.0), &mut encryption_generator);
        }

        let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);

        for (lwe, mut glwe) in lev.iter().zip(glev.iter_mut()) {
            convert_lwe_to_glwe_by_trace_with_preprocessing_high_prec(&lwe, &mut glwe, &fourier_glwe_dsk_to_large, &fourier_glwe_dsk_from_large, &auto_keys);
        }

        let glwe = glev.get(0);
        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if i == 0 {(msg << (Scalar::BITS as usize - ggsw_base_log.0))} else {Scalar::ZERO}
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &glwe, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &glwe, &correct_val_list);

        glev_l_infty_err_list.push(max_err);
        glev_l2_err_list.push(l2_err);


        let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);
        switch_scheme(&glev, &mut ggsw, ss_key);

        let glwe_list = ggsw.as_glwe_list();
        let output = glwe_list.get(0);

        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if msg == 0 {
                Scalar::ZERO
            } else {
                let glwe_sk_val = *glwe_sk_poly.as_ref().get(i).unwrap();
                glwe_sk_val.wrapping_neg() << (Scalar::BITS as usize - ggsw_base_log.0)
            }
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &output, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &output, &correct_val_list);

        ggsw_l_infty_err_list.push(max_err);
        ggsw_l2_err_list.push(l2_err);
    }

    println!("Lev -> GLev by Trace");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in glev_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in glev_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());

    println!("GLev -> GGSW by Scheme Switching");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in ggsw_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in ggsw_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}


#[allow(unused)]
fn sample_ggsw_conv_err_by_pfks(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: StandardDev,
    pfks_base_log: DecompositionBaseLog,
    pfks_level: DecompositionLevelCount,
    num_repeat: usize,
) {
    println!("GGSW conversion by pfks");
    println!(
        "N: {}, k: {}, B_pfks: 2^{}, l_pfks: {}",
        polynomial_size.0, glwe_dimension.0, pfks_base_log.0, pfks_level.0,
    );

    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let pfpksk_list = allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &lwe_sk,
        &glwe_sk,
        pfks_base_log,
        pfks_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let pfpksk = pfpksk_list.get(0);

    let mut rng = rand::thread_rng();

    let mut l_infty_err_list = vec![];
    let mut l2_err_list = vec![];

    let glwe_sk_poly_list = glwe_sk.as_polynomial_list();
    let glwe_sk_poly = glwe_sk_poly_list.get(0);

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..2) as Scalar;
        let pt = Plaintext(msg << (Scalar::BITS - 1));

        let input = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            pt,
            StandardDev(0.0),
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            &pfpksk,
            &mut output,
            &input,
        );

        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if msg == 0 {
                Scalar::ZERO
            } else {
                glwe_sk_poly.as_ref().get(i).unwrap() << (Scalar::BITS - 1)
            }
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &output, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &output, &correct_val_list);

        l_infty_err_list.push(max_err);
        l2_err_list.push(l2_err);
    }

    println!("GGSW Conv by PrivKS");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}
