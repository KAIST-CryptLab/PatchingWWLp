use std::time::Instant;

use patching_wwlp::{allocate_and_generate_new_glwe_keyswitch_key, convert_standard_glwe_keyswitch_key_to_fourier, get_val_and_abs_err, keyswitch_lwe_ciphertext_by_glwe_keyswitch, FftType, FourierGlweKeyswitchKey};
use tfhe::core_crypto::prelude::*;

type Scalar = u64;
const FFT_TYPE: FftType = FftType::Split16;

fn main() {
    let common_polynomial_size = PolynomialSize(256);
    let src_glwe_dimension = GlweDimension(8);
    let dst_glwe_dimension = GlweDimension(3);

    let src_lwe_dimension = LweDimension(common_polynomial_size.0 * src_glwe_dimension.0);
    let src_lwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);

    let dst_lwe_dimension = LweDimension(common_polynomial_size.0 * dst_glwe_dimension.0);
    let dst_lwe_size = dst_lwe_dimension.to_lwe_size();
    let dst_lwe_modular_std_dev = StandardDev(2.0f64.powf(-17.12));

    let lwe_ks_base_log = DecompositionBaseLog(6);
    let lwe_ks_level = DecompositionLevelCount(2);

    let glwe_ks_base_log = DecompositionBaseLog(4);
    let glwe_ks_level = DecompositionLevelCount(3);

    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let src_lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(src_lwe_dimension, &mut secret_generator);
    let src_glwe_sk = GlweSecretKey::from_container(src_lwe_sk.as_ref(), common_polynomial_size);
    let src_glwe_size = src_glwe_sk.glwe_dimension().to_glwe_size();

    let dst_lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(dst_lwe_dimension, &mut secret_generator);
    let dst_glwe_sk = GlweSecretKey::from_container(dst_lwe_sk.as_ref(), common_polynomial_size);
    let dst_glwe_size = dst_glwe_sk.glwe_dimension().to_glwe_size();

    let lwe_ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &src_lwe_sk,
        &dst_lwe_sk,
        lwe_ks_base_log,
        lwe_ks_level,
        dst_lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let glwe_ksk = allocate_and_generate_new_glwe_keyswitch_key(
        &src_glwe_sk,
        &dst_glwe_sk,
        glwe_ks_base_log,
        glwe_ks_level,
        dst_lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_ksk = FourierGlweKeyswitchKey::new(
        src_glwe_size,
        dst_glwe_size,
        common_polynomial_size,
        glwe_ks_base_log,
        glwe_ks_level,
        FFT_TYPE,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&glwe_ksk, &mut fourier_glwe_ksk);

    // Set input LWE
    let input = allocate_and_encrypt_new_lwe_ciphertext(
        &src_lwe_sk,
        Plaintext(0),
        src_lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut output = LweCiphertext::new(Scalar::ZERO, dst_lwe_size, ciphertext_modulus);

    let num_warmup = 100;
    let num_repeat = 100;

    // LWE KS
    for _ in 0..num_warmup {
        keyswitch_lwe_ciphertext(&lwe_ksk, &input, &mut output);
    }

    let now = Instant::now();
    for _ in 0..num_repeat {
        keyswitch_lwe_ciphertext(&lwe_ksk, &input, &mut output);
    }
    let time_lwe_ks = now.elapsed();
    let (_, abs_err) = get_val_and_abs_err(&dst_lwe_sk, &output, Scalar::ZERO, 1);
    println!("LWE KS: {} ms, {:.2} bits", (time_lwe_ks.as_micros() as f64) / ((num_repeat * 1000) as f64), (abs_err as f64).log2());

    for _ in 0..num_warmup {
        keyswitch_lwe_ciphertext_by_glwe_keyswitch(&input, &mut output, &fourier_glwe_ksk);
    }

    let now = Instant::now();
    for _ in 0..num_repeat {
        keyswitch_lwe_ciphertext_by_glwe_keyswitch(&input, &mut output, &fourier_glwe_ksk);
    }
    let time_glwe_ks = now.elapsed();

    let (_, abs_err) = get_val_and_abs_err(&dst_lwe_sk, &output, Scalar::ZERO, 1);
    println!("LWE KS by GLWE KS: {} ms, {:.2} bits", (time_glwe_ks.as_micros() as f64) / ((num_repeat * 1000) as f64), (abs_err as f64).log2());
}