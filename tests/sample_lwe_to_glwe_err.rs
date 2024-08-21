use patching_wwlp::{convert_lwe_to_glwe_by_trace_with_preprocessing, gen_all_auto_keys, get_glwe_l2_err, get_glwe_max_err, FftType, auto_conv_instance::*};
use rand::Rng;
use tfhe::core_crypto::prelude::*;

type Scalar = u64;
const NUM_REPEAT: usize = 1000;

fn main() {
    /* LWE to GLWE by trace with preprocessing */
    // -------- param_message_2_carry_2 -------- //
    let param = *AUTO_PARAM_2_2_VANILLA;
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type = param.fft_type();

    let modulus_sup = 16;
    let log_scale = 59;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    let param = *AUTO_PARAM_2_2_LEV_3;
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type = param.fft_type();

    let modulus_sup = 16;
    let log_scale = 59;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    // -------- param_message_3_carry_3 -------- //
    let param = *AUTO_PARAM_3_3_LEV_4;
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type = param.fft_type();

    let modulus_sup = 64;
    let log_scale = 57;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    let param = *AUTO_PARAM_3_3_LEV_5;
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type = param.fft_type();

    let modulus_sup = 64;
    let log_scale = 57;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    // -------- message_4_carry_4 -------- //
    let param = *AUTO_PARAM_4_4_LEV_3;
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type = param.fft_type();

    let modulus_sup = 256;
    let log_scale = 55;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    let param = *AUTO_PARAM_4_4_LEV_4;
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type = param.fft_type();

    let modulus_sup = 256;
    let log_scale = 55;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    /* LWE to GLWE by packing keyswitching */
    // -------- param_message_2_carry_2 -------- //
    let param = *PKSK_PARAM_2_2;
    let lwe_dimension = param.lwe_dimension();
    let lwe_modular_std_dev = param.lwe_modular_std_dev();
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pksk_base_log = param.pksk_base_log();
    let pksk_level = param.pksk_level();
    let ks_base_log = param.ks_base_log();
    let ks_level = param.ks_level();

    let modulus_sup = 16;
    let log_scale = 59;

    sample_lwe_to_glwe_by_large_pksk(polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, modulus_sup, log_scale, NUM_REPEAT);
    sample_lwe_to_glwe_by_small_pksk(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, ks_base_log, ks_level, modulus_sup, log_scale, NUM_REPEAT);

    // -------- param_message_3_carry_3 -------- //
    let param = *PKSK_PARAM_3_3;
    let lwe_dimension = param.lwe_dimension();
    let lwe_modular_std_dev = param.lwe_modular_std_dev();
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pksk_base_log = param.pksk_base_log();
    let pksk_level = param.pksk_level();
    let ks_base_log = param.ks_base_log();
    let ks_level = param.ks_level();

    let modulus_sup = 64;
    let log_scale = 57;

    sample_lwe_to_glwe_by_large_pksk(polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, modulus_sup, log_scale, NUM_REPEAT);
    sample_lwe_to_glwe_by_small_pksk(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, ks_base_log, ks_level, modulus_sup, log_scale, NUM_REPEAT);

    // -------- param_message_4_carry_4 -------- //
    let param = *PKSK_PARAM_4_4;
    let lwe_dimension = param.lwe_dimension();
    let lwe_modular_std_dev = param.lwe_modular_std_dev();
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pksk_base_log = param.pksk_base_log();
    let pksk_level = param.pksk_level();
    let ks_base_log = param.ks_base_log();
    let ks_level = param.ks_level();

    let modulus_sup = 256;
    let log_scale = 55;

    sample_lwe_to_glwe_by_large_pksk(polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, modulus_sup, log_scale, NUM_REPEAT);
    sample_lwe_to_glwe_by_small_pksk(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, ks_base_log, ks_level, modulus_sup, log_scale, NUM_REPEAT);
}

#[allow(unused)]
fn sample_lwe_to_glwe_by_trace_with_preprocessing(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    modulus_sup: usize,
    log_scale: usize,
    fft_type: FftType,
    num_repeat: usize,
) {
    println!("lwe to glwe by trace with preprocessing");
    println!("N: {}, k: {}, B_auto: 2^{}, l_auto: {}, fft type: {:?}",
        polynomial_size.0, glwe_dimension.0, auto_base_log.0, auto_level.0, fft_type
    );

    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let mut rng = rand::thread_rng();

    let mut l_infty_err_list = vec![];
    let mut l2_err_list = vec![];

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..modulus_sup) as Scalar;
        let pt = Plaintext(msg << log_scale);

        let mut input = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            pt,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        convert_lwe_to_glwe_by_trace_with_preprocessing(&input, &mut output, &auto_keys);

        let max_err = get_glwe_max_err(
            &glwe_sk,
            &output,
            &PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                if i == 0 {msg << log_scale} else {Scalar::ZERO}
            }).collect::<Vec<Scalar>>())
        );
        let l2_err = get_glwe_l2_err(
            &glwe_sk,
            &output,
            &PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                if i == 0 {msg << log_scale} else {Scalar::ZERO}
            }).collect::<Vec<Scalar>>())
        );

        l_infty_err_list.push(max_err);
        l2_err_list.push(l2_err);
    }

    println!("LWEtoGLWE err");
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

#[allow(unused)]
fn sample_lwe_to_glwe_by_large_pksk(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    pksk_base_log: DecompositionBaseLog,
    pksk_level: DecompositionLevelCount,
    modulus_sup: usize,
    log_scale: usize,
    num_repeat: usize,
) {
    println!("lwe to glwe by large pksk");
    println!("N: {}, k: {}, B_pksk: 2^{}, l_pksk: {}",
        polynomial_size.0, glwe_dimension.0, pksk_base_log.0, pksk_level.0
    );

    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &lwe_sk,
        &glwe_sk,
        pksk_base_log,
        pksk_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut rng = rand::thread_rng();

    let mut l_infty_err_list = vec![];
    let mut l2_err_list = vec![];

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..modulus_sup) as Scalar;
        let pt = Plaintext(msg << log_scale);

        let input = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            pt,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            &pksk,
            &input,
            &mut output,
        );

        let max_err = get_glwe_max_err(
            &glwe_sk,
            &output,
            &PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                if i == 0 {msg << log_scale} else {Scalar::ZERO}
            }).collect::<Vec<Scalar>>())
        );
        let l2_err = get_glwe_l2_err(
            &glwe_sk,
            &output,
            &PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                if i == 0 {msg << log_scale} else {Scalar::ZERO}
            }).collect::<Vec<Scalar>>())
        );

        l_infty_err_list.push(max_err);
        l2_err_list.push(l2_err);
    }

    println!("LWEtoGLWE err");
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

#[allow(unused)]
fn sample_lwe_to_glwe_by_small_pksk(
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: impl DispersionParameter,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    pksk_base_log: DecompositionBaseLog,
    pksk_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    modulus_sup: usize,
    log_scale: usize,
    num_repeat: usize,
) {
    println!("lwe to glwe by small pksk");
    println!("n: {}, N: {}, k: {}, B_pksk: 2^{}, l_pksk: {}, B_ks: 2^{}, l_ks: {}",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pksk_base_log.0, pksk_level.0, ks_base_log.0, ks_level.0
    );

    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let lwe_sk_after_ks = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);

    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &lwe_sk,
        &lwe_sk_after_ks,
        ks_base_log,
        ks_level,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &lwe_sk_after_ks,
        &glwe_sk,
        pksk_base_log,
        pksk_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut rng = rand::thread_rng();

    let mut l_infty_err_list = vec![];
    let mut l2_err_list = vec![];

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..modulus_sup) as Scalar;
        let pt = Plaintext(msg << log_scale);

        let input = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            pt,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut input_ks = LweCiphertext::new(Scalar::ZERO, lwe_dimension.to_lwe_size(), ciphertext_modulus);
        let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        keyswitch_lwe_ciphertext(
            &ksk,
            &input,
            &mut input_ks,
        );

        keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            &pksk,
            &input_ks,
            &mut output,
        );

        let max_err = get_glwe_max_err(
            &glwe_sk,
            &output,
            &PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                if i == 0 {msg << log_scale} else {Scalar::ZERO}
            }).collect::<Vec<Scalar>>())
        );
        let l2_err = get_glwe_l2_err(
            &glwe_sk,
            &output,
            &PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                if i == 0 {msg << log_scale} else {Scalar::ZERO}
            }).collect::<Vec<Scalar>>())
        );

        l_infty_err_list.push(max_err);
        l2_err_list.push(l2_err);
    }

    println!("LWEtoGLWE");
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
