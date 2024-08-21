use std::time::{Duration, Instant};
use rand::Rng;
use tfhe::core_crypto::prelude::*;
use patching_wwlp::{
    automorphism::{gen_all_auto_keys, trace_assign}, fourier_glwe_keyswitch::FftType, get_glwe_l2_err, glwe_conv::convert_lwe_to_glwe_const, mod_switch::lwe_preprocessing_assign, utils::get_glwe_max_err
};

type Scalar = u64;
const NUM_WARMUP: usize = 1000;

fn main() {
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);

    let auto_base_log = DecompositionBaseLog(12);
    let auto_level = DecompositionLevelCount(4);
    let fft_type = FftType::Split(43);

    test_lwe_to_glwe(
        polynomial_size,
        glwe_dimension,
        glwe_modular_std_dev,
        auto_base_log,
        auto_level,
        fft_type,
    );
}

fn test_lwe_to_glwe(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: StandardDev,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    fft_type: FftType,
) {
    println!("PolynomialSize: {}, GlweDim: {}, AutoBaseLog: {}, AutoLevel: {}, fft type: {:?}",
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

    // Set input LWE
    let modulus_bit = 4usize;
    let modulus_sup = 1 << modulus_bit;
    let log_scale = Scalar::BITS as usize - (modulus_bit + 1);

    let mut rng = rand::thread_rng();
    let msg = rng.gen_range(0..modulus_sup) as Scalar;
    let pt = Plaintext(msg << log_scale);

    let mut input = allocate_and_encrypt_new_lwe_ciphertext(
        &lwe_sk,
        pt,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        if i == 0 {msg << log_scale} else {Scalar::ZERO}
    }).collect::<Vec<Scalar>>());

    let mut time = Duration::ZERO;

    // Pre-processing
    let now = Instant::now();
    lwe_preprocessing_assign(&mut input, polynomial_size);
    time += now.elapsed();

    // LWEtoGLWEConst
    let now = Instant::now();
    let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    convert_lwe_to_glwe_const(&input, &mut output);
    time += now.elapsed();

    // EvalTr
    for _ in 0..NUM_WARMUP {
        // warm-up
        let mut tmp = output.clone();
        trace_assign(&mut tmp, &auto_keys);
    }

    let now = Instant::now();
    trace_assign(&mut output, &auto_keys);
    time += now.elapsed();

    let max_err = get_glwe_max_err(
        &glwe_sk,
        &output,
        &correct_val_list,
    );
    let l2_err = get_glwe_l2_err(
        &glwe_sk,
        &output,
        &correct_val_list
    );

    println!("{} ms, err: (Max) {:.2} bits (l2) {:.2} bits", time.as_micros() as f64 / 1000f64, (max_err as f64).log2(), l2_err.log2());
}