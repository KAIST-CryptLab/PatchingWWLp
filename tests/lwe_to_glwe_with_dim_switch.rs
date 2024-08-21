use std::time::Instant;

use patching_wwlp::{allocate_and_generate_new_glwe_keyswitch_key, convert_lwe_to_glwe_const, convert_standard_glwe_keyswitch_key_to_fourier, gen_all_auto_keys, get_glwe_l2_err, get_glwe_max_err, get_val_and_abs_err, glwe_preprocessing_assign, keyswitch_glwe_ciphertext, trace_assign, FftType, FourierGlweKeyswitchKey};
use tfhe::core_crypto::prelude::*;

type Scalar = u64;

fn main() {
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let large_glwe_dimension = GlweDimension(2);
    let large_glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);

    let glwe_ks_base_log_to_large = DecompositionBaseLog(15);
    let glwe_ks_level_to_large = DecompositionLevelCount(3);
    let fft_type_to_large = FftType::Split(44);

    let glwe_ks_base_log_from_large = DecompositionBaseLog(5);
    let glwe_ks_level_from_large = DecompositionLevelCount(10);
    let fft_type_from_large = FftType::Split(35);

    let auto_base_log = DecompositionBaseLog(6);
    let auto_level = DecompositionLevelCount(10);
    let fft_type_auto = FftType::Split(36);

    test_lwe_to_glwe_with_dim_switch(
        polynomial_size,
        glwe_dimension,
        glwe_modular_std_dev,
        large_glwe_dimension,
        large_glwe_modular_std_dev,
        glwe_ks_base_log_to_large,
        glwe_ks_level_to_large,
        glwe_ks_base_log_from_large,
        glwe_ks_level_from_large,
        auto_base_log,
        auto_level,
        fft_type_to_large,
        fft_type_from_large,
        fft_type_auto,
    );
}

fn test_lwe_to_glwe_with_dim_switch(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    large_glwe_dimension: GlweDimension,
    large_glwe_modular_std_dev: impl DispersionParameter,
    glwe_ks_base_log_to_large: DecompositionBaseLog,
    glwe_ks_level_to_large: DecompositionLevelCount,
    glwe_ks_base_log_from_large: DecompositionBaseLog,
    glwe_ks_level_from_large: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    fft_type_to_large: FftType,
    fft_type_from_large: FftType,
    fft_type_auto: FftType,
) {
    println!(
"N: {}, k: {}, k_large: {}
B_to_large: 2^{}, l_to_large: {}, fft_type_to_large: {:?}
B_from_large: 2^{}, l_from_large: {}, fft_type_from_large: {:?}
B_auto: 2^{}, l_auto: {}, fft_type_auto: {:?}",
        polynomial_size.0, glwe_dimension.0, large_glwe_dimension.0,
        glwe_ks_base_log_to_large.0, glwe_ks_level_to_large.0, fft_type_to_large,
        glwe_ks_base_log_from_large.0, glwe_ks_level_from_large.0, fft_type_from_large,
        auto_base_log.0, auto_level.0, fft_type_auto,
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

    let large_glwe_size = large_glwe_dimension.to_glwe_size();
    let large_glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(large_glwe_dimension, polynomial_size, &mut secret_generator);
    let large_lwe_sk = large_glwe_sk.clone().into_lwe_secret_key();

    let glwe_ksk_to_large = allocate_and_generate_new_glwe_keyswitch_key(
        &glwe_sk,
        &large_glwe_sk,
        glwe_ks_base_log_to_large,
        glwe_ks_level_to_large,
        large_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_ksk_to_large = FourierGlweKeyswitchKey::new(
        glwe_size,
        large_glwe_size,
        polynomial_size,
        glwe_ks_base_log_to_large,
        glwe_ks_level_to_large,
        fft_type_to_large,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&glwe_ksk_to_large, &mut fourier_glwe_ksk_to_large);

    let glwe_ksk_from_large = allocate_and_generate_new_glwe_keyswitch_key(
        &large_glwe_sk,
        &glwe_sk,
        glwe_ks_base_log_from_large,
        glwe_ks_level_from_large,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_ksk_from_large = FourierGlweKeyswitchKey::new(
        large_glwe_size,
        glwe_size,
        polynomial_size,
        glwe_ks_base_log_from_large,
        glwe_ks_level_from_large,
        fft_type_from_large,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&glwe_ksk_from_large, &mut fourier_glwe_ksk_from_large);

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type_auto,
        &large_glwe_sk,
        large_glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Set input ciphertext
    let lwe_input = allocate_and_encrypt_new_lwe_ciphertext(
        &lwe_sk,
        Plaintext(0),
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut glwe = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    convert_lwe_to_glwe_const(&lwe_input, &mut glwe);

    // GlweKS to large
    let mut glwe_large = GlweCiphertext::new(Scalar::ZERO, large_glwe_size, polynomial_size, ciphertext_modulus);

    for _ in 0..100 {
        // warm-up
        keyswitch_glwe_ciphertext(&fourier_glwe_ksk_to_large, &glwe, &mut glwe_large);
    }

    let now = Instant::now();
    keyswitch_glwe_ciphertext(&fourier_glwe_ksk_to_large, &glwe, &mut glwe_large);
    let time = now.elapsed();
    println!("GLWE KS to large dim: {} ms", time.as_micros() as f64 / 1000f64);

    let mut buf = LweCiphertext::new(Scalar::ZERO, large_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
    extract_lwe_sample_from_glwe_ciphertext(&glwe_large, &mut buf, MonomialDegree(0));
    let (_, err) = get_val_and_abs_err(&large_lwe_sk, &buf, Scalar::ZERO, Scalar::ONE);
    println!("  Err: {:.2} bits", (err as f64).log2());

    // GLWE preprocessing
    glwe_preprocessing_assign(&mut glwe_large);

    // Trace
    let now = Instant::now();
    trace_assign(&mut glwe_large, &auto_keys);
    let time = now.elapsed();
    println!("Trace eval: {} ms", time.as_micros() as f64 / 1000f64);

    let mut buf = LweCiphertext::new(Scalar::ZERO, large_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
    extract_lwe_sample_from_glwe_ciphertext(&glwe_large, &mut buf, MonomialDegree(0));
    let (_, err) = get_val_and_abs_err(&large_lwe_sk, &buf, Scalar::ZERO, Scalar::ONE);
    println!("  Err: {:.2} bits", (err as f64).log2());

    // GlweKS from large
    let mut glwe_out = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let now = Instant::now();
    keyswitch_glwe_ciphertext(&fourier_glwe_ksk_from_large, &glwe_large, &mut glwe_out);
    let time = now.elapsed();
    println!("GLWE KS from large dim: {} ms", time.as_micros() as f64 / 1000f64);

    // Decryption
    let correct_val_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    let max_err = get_glwe_max_err(
        &glwe_sk,
        &glwe_out,
        &correct_val_list,
    );
    let l2_err = get_glwe_l2_err(
        &glwe_sk,
        &glwe_out,
        &correct_val_list,
    );
    println!();
    println!("Output GLWE ctxt err: (Max) {:.2} bits (l2) {:.2} bits", (max_err as f64).log2(), l2_err.log2());
}