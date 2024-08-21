use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;
use patching_wwlp::{
    automorphism::gen_all_auto_keys, glwe_conv::*, auto_conv_instance::*,
};

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10000);
    targets =
        criterion_benchmark_trace_with_preprocessing,
        criterion_benchmark_small_pksk,
        criterion_benchmark_large_pksk,
);
criterion_main!(benches);


#[allow(unused)]
fn criterion_benchmark_trace_with_preprocessing(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwe_to_glwe_conversion");

    let param_list = [
        (*AUTO_PARAM_2_2_VANILLA, "param_2_2_vanilla", 59),
        (*AUTO_PARAM_2_2_LEV_3, "param_2_2_lev_3", 59),
        (*AUTO_PARAM_3_3_LEV_4, "param_3_3_lev_4", 57),
        (*AUTO_PARAM_3_3_LEV_5, "param_3_3_lev_5", 57),
        (*AUTO_PARAM_4_4_LEV_3, "param_4_4_lev_3", 55),
        (*AUTO_PARAM_4_4_LEV_4, "param_4_4_lev_4", 55),
    ];

    for (param, id, log_scale) in param_list.iter() {
        let polynomial_size = param.polynomial_size();
        let glwe_dimension = param.glwe_dimension();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let auto_base_log = param.auto_base_log();
        let auto_level = param.auto_level();
        let fft_type = param.fft_type();
        let ciphertext_modulus = param.ciphertext_modulus();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let glwe_size = glwe_dimension.to_glwe_size();
        let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
        let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            fft_type,
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        // Set input LWE ciphertext
        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            Plaintext(0),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut glwe = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "lwe_to_glwe_by_trace_with_preprocessing",
                id,
            ),
            |b| b.iter(
                || convert_lwe_to_glwe_by_trace_with_preprocessing(
                    black_box(&lwe),
                    black_box(&mut glwe),
                    black_box(&auto_keys),
                )
            ),
        );

        // Error
        let mut pt = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);

        let mut max_err = 0;
        for val in pt.as_ref().iter() {
            let rounding = val & (1 << (log_scale - 1));
            let decoded = val.wrapping_add(rounding) >> log_scale;
            assert_eq!(decoded, 0);

            let val = *val;
            let abs_err = {
                let d0 = 0.wrapping_sub(val);
                let d1 = val.wrapping_sub(0);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        let max_err = (max_err as f64).log2();

        println!(
            "N: {}, k: {}, l_auto: {}, B_auto: 2^{}, fft type: {:?}, err: {:.2} bits",
            polynomial_size.0, glwe_dimension.0, auto_level.0, auto_base_log.0, fft_type, max_err
        );
    }
}

#[allow(unused)]
fn criterion_benchmark_large_pksk(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwe_to_glwe_conversion");

    let param_list = [
        (*PKSK_PARAM_2_2, "param_2_2_large_pksk", 59),
        (*PKSK_PARAM_3_3, "param_3_3_large_pksk", 57),
        (*PKSK_PARAM_4_4, "param_4_4_large_pksk", 55),
    ];

    for (param, id, log_scale) in param_list.iter() {
        let polynomial_size = param.polynomial_size();
        let glwe_dimension = param.glwe_dimension();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let pksk_base_log = param.pksk_base_log();
        let pksk_level = param.pksk_level();
        let ciphertext_modulus = param.ciphertext_modulus();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let glwe_size = glwe_dimension.to_glwe_size();
        let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
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

        // Set input LWE ciphertext
        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            Plaintext(0),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut glwe = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "large_pksk",
                id,
            ),
            |b| b.iter(
                || keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                    black_box(&pksk),
                    black_box(&lwe),
                    black_box(&mut glwe),
                )
            ),
        );

        // Error
        let mut pt = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);

        let mut max_err = 0;
        for val in pt.as_ref().iter() {
            let rounding = val & (1 << (log_scale - 1));
            let decoded = val.wrapping_add(rounding) >> log_scale;
            assert_eq!(decoded, 0);

            let val = *val;
            let abs_err = {
                let d0 = 0.wrapping_sub(val);
                let d1 = val.wrapping_sub(0);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        let max_err = (max_err as f64).log2();

        println!(
            "N: {}, k: {}, l_pksk: {}, B_pksk: 2^{}, err: {:.2} bits",
            polynomial_size.0, glwe_dimension.0, pksk_level.0, pksk_base_log.0, max_err
        );
    }
}

#[allow(unused)]
fn criterion_benchmark_small_pksk(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwe_to_glwe_conversion");

    let param_list = [
        (*PKSK_PARAM_2_2, "param_2_2_small_pksk", 59),
        (*PKSK_PARAM_3_3, "param_3_3_small_pksk", 57),
        (*PKSK_PARAM_4_4, "param_4_4_small_pksk", 55),
    ];


    for (param, id, log_scale) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let polynomial_size = param.polynomial_size();
        let glwe_dimension = param.glwe_dimension();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let ks_base_log = param.ks_base_log();
        let ks_level = param.ks_level();
        let pksk_base_log = param.pksk_base_log();
        let pksk_level = param.pksk_level();
        let ciphertext_modulus = param.ciphertext_modulus();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
        let glwe_size = glwe_dimension.to_glwe_size();
        let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
        let large_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &large_lwe_sk,
            &lwe_sk,
            ks_base_log,
            ks_level,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
            &lwe_sk,
            &glwe_sk,
            pksk_base_log,
            pksk_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        // Set input LWE ciphertext
        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &large_lwe_sk,
            Plaintext(0),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut lwe_small = LweCiphertext::new(0, lwe_dimension.to_lwe_size(), ciphertext_modulus);
        let mut glwe = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "small_pksk",
                id,
            ),
            |b| b.iter(
                || {
                    keyswitch_lwe_ciphertext(
                        black_box(&ksk),
                        black_box(&lwe),
                        black_box(&mut lwe_small),
                    );
                    keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                    black_box(&pksk),
                    black_box(&lwe_small),
                    black_box(&mut glwe),
                    );
                }
            ),
        );

        // Error
        let mut pt = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);

        let mut max_err = 0;
        for val in pt.as_ref().iter() {
            let rounding = val & (1 << (log_scale - 1));
            let decoded = val.wrapping_add(rounding) >> log_scale;
            assert_eq!(decoded, 0);

            let val = *val;
            let abs_err = {
                let d0 = 0.wrapping_sub(val);
                let d1 = val.wrapping_sub(0);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        let max_err = (max_err as f64).log2();

        println!(
            "N: {}, k: {}, l_pksk: {}, B_pksk: 2^{}, err: {:.2} bits",
            polynomial_size.0, glwe_dimension.0, pksk_level.0, pksk_base_log.0, max_err
        );
    }
}
