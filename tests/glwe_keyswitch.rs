use std::time::Instant;

use tfhe::core_crypto::prelude::*;
use patching_wwlp::{fourier_glwe_keyswitch::*, get_glwe_l2_err, glwe_keyswitch::*, utils::get_glwe_max_err};

type Scalar = u64;
const FFT_TYPE: FftType = FftType::Split(40);

fn main() {
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let large_glwe_dimension = GlweDimension(2);
    let large_glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

    let decomp_level_count_to_small = DecompositionLevelCount(10);
    let decomp_base_log_to_small = DecompositionBaseLog(4);

    let decomp_level_count_to_large = DecompositionLevelCount(3);
    let decomp_base_log_to_large = DecompositionBaseLog(15);

    test_glwe_keyswitch(
        polynomial_size,
        glwe_dimension,
        glwe_modular_std_dev,
        large_glwe_dimension,
        large_glwe_modular_std_dev,
        decomp_base_log_to_small,
        decomp_level_count_to_small,
        decomp_base_log_to_large,
        decomp_level_count_to_large,
        ciphertext_modulus,
    );
}

fn test_glwe_keyswitch(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    large_glwe_dimension: GlweDimension,
    large_glwe_modular_std_dev: impl DispersionParameter,
    decomp_base_log_to_small: DecompositionBaseLog,
    decomp_level_count_to_small: DecompositionLevelCount,
    decomp_base_log_to_large: DecompositionBaseLog,
    decomp_level_count_to_large: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
) {
    println!(
        "N: {}, k_small: {}, k_large: {}",
        polynomial_size.0, glwe_dimension.0, large_glwe_dimension.0,
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    let large_glwe_size = large_glwe_dimension.to_glwe_size();
    let large_glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(large_glwe_dimension, polynomial_size, &mut secret_generator);

    // Set input
    let pt = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));

    let mut ct = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut large_ct = GlweCiphertext::new(Scalar::ZERO, large_glwe_size, polynomial_size, ciphertext_modulus);

    encrypt_glwe_ciphertext(&glwe_sk, &mut ct, &pt, glwe_modular_std_dev, &mut encryption_generator);
    encrypt_glwe_ciphertext(&large_glwe_sk, &mut large_ct, &pt, large_glwe_modular_std_dev, &mut encryption_generator);

    // Error of fresh ciphertexts
    let max_err = get_glwe_max_err(&glwe_sk, &ct, &pt);
    println!("Fresh GLWE ctxt err: {:.2} bits", (max_err as f64).log2());

    let max_err = get_glwe_max_err(&large_glwe_sk, &large_ct, &pt);
    println!("Fresh large GLWE ctxt err: {:.2} bits", (max_err as f64).log2());
    println!();

    // Test Glwe Keyswitching: Large -> Small
    println!(
        "GLWE Keyswitching Large -> Small: B = 2^{}, l = {}",
        decomp_base_log_to_small.0, decomp_level_count_to_small.0,
    );
    let standard_glwe_ksk = allocate_and_generate_new_glwe_keyswitch_key(
        &large_glwe_sk,
        &glwe_sk,
        decomp_base_log_to_small,
        decomp_level_count_to_small,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_ksk = FourierGlweKeyswitchKey::new(
        large_glwe_size,
        glwe_size,
        polynomial_size,
        decomp_base_log_to_small,
        decomp_level_count_to_small,
        FFT_TYPE,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&standard_glwe_ksk, &mut fourier_glwe_ksk);


    let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    // warm-up
    for _ in 0..100 {
        standard_keyswitch_glwe_ciphertext(
            &standard_glwe_ksk,
            &large_ct,
            &mut output,
        );
        keyswitch_glwe_ciphertext(
            &fourier_glwe_ksk,
            &large_ct,
            &mut output,
        );
    }

    let num_repeat = 100;
    let now = Instant::now();
    for _ in 0..num_repeat {
        standard_keyswitch_glwe_ciphertext(
            &standard_glwe_ksk,
            &large_ct,
            &mut output,
        );
    }
    let time_to_small = now.elapsed();

    let max_err = get_glwe_max_err(&glwe_sk, &output, &pt);
    let l2_err = get_glwe_l2_err(&glwe_sk, &output, &pt);
    println!(
        "[Standard] GLWE KS large -> small: {} ms, (Max) {:.2} bits (l2) {:.2} bits",
        time_to_small.as_millis() as f64 / num_repeat as f64,
        (max_err as f64).log2(),
        l2_err.log2(),
    );

    let now = Instant::now();
    for _ in 0..num_repeat {
        keyswitch_glwe_ciphertext(
            &fourier_glwe_ksk,
            &large_ct,
            &mut output,
        );
    }
    let time_to_small_fourier = now.elapsed();

    let max_err = get_glwe_max_err(&glwe_sk, &output, &pt);
    let l2_err = get_glwe_l2_err(&glwe_sk, &output, &pt);
    println!(
        "[Fourier]  GLWE KS large -> small: {} ms, (Max) {:.2} bits (l2) {:.2} bits",
        time_to_small_fourier.as_millis() as f64 / num_repeat as f64,
        (max_err as f64).log2(),
        l2_err.log2(),
    );
    println!();

    // Test Glwe Keyswitching: Small -> Large
    println!(
        "GLWE Keyswitching Small -> Large: B = 2^{}, l = {}",
        decomp_base_log_to_large.0, decomp_level_count_to_large.0,
    );
    let standard_glwe_ksk = allocate_and_generate_new_glwe_keyswitch_key(
        &glwe_sk,
        &large_glwe_sk,
        decomp_base_log_to_large,
        decomp_level_count_to_large,
        large_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_ksk = FourierGlweKeyswitchKey::new(
        glwe_size,
        large_glwe_size,
        polynomial_size,
        decomp_base_log_to_large,
        decomp_level_count_to_large,
        FFT_TYPE,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&standard_glwe_ksk, &mut fourier_glwe_ksk);

    let mut output = GlweCiphertext::new(Scalar::ZERO, large_glwe_size, polynomial_size, ciphertext_modulus);

    let now = Instant::now();
    for _ in 0..num_repeat {
        standard_keyswitch_glwe_ciphertext(
            &standard_glwe_ksk,
            &ct,
            &mut output,
        );
    }
    let time_to_large = now.elapsed();

    let max_err = get_glwe_max_err(&large_glwe_sk, &output, &pt);
    let l2_err = get_glwe_l2_err(&large_glwe_sk, &output, &pt);
    println!(
        "[Standard] GLWE KS small -> large: {} ms, (Max) {:.2} bits (l2) {:.2} bits",
        time_to_large.as_millis() as f64 / num_repeat as f64,
        (max_err as f64).log2(),
        l2_err.log2(),
    );

    let now = Instant::now();
    for _ in 0..num_repeat {
        keyswitch_glwe_ciphertext(
            &fourier_glwe_ksk,
            &ct,
            &mut output,
        );
    }
    let time_to_large_fourier = now.elapsed();

    let max_err = get_glwe_max_err(&large_glwe_sk, &output, &pt);
    let l2_err = get_glwe_l2_err(&large_glwe_sk, &output, &pt);
    println!(
        "[Fourier]  GLWE KS small -> large: {} ms, (Max) {:.2} bits (l2) {:.2} bits",
        time_to_large_fourier.as_millis() as f64 / num_repeat as f64,
        (max_err as f64).log2(),
        l2_err.log2(),
    );
}
