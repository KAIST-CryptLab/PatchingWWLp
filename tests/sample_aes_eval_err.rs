use rand::Rng;
use tfhe::core_crypto::prelude::*;
use patching_wwlp::{
    automorphism::gen_all_auto_keys, byte_array_to_mat, generate_scheme_switching_key, get_he_state_error, he_add_round_key, he_mix_columns, he_shift_rows, he_sub_bytes_by_patched_wwlp_cbs, keygen_pbs_with_glwe_ds, keyswitch_lwe_ciphertext_by_glwe_keyswitch, Aes128Ref, aes_params::*, aes_instances::*, BLOCKSIZE_IN_BIT, BLOCKSIZE_IN_BYTE, BYTESIZE, NUM_ROUNDS
};

fn main() {
    sample_aes_eval_err(*AES_SET_1);
}

#[allow(unused)]
fn sample_aes_eval_err(
    param: AesParam<u64>,
) {
    let lwe_dimension = param.lwe_dimension();
    let glwe_dimension = param.glwe_dimension();
    let polynomial_size = param.polynomial_size();
    let lwe_modular_std_dev = param.lwe_modular_std_dev();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pbs_base_log = param.pbs_base_log();
    let pbs_level = param.pbs_level();
    let glwe_ds_base_log = param.glwe_ds_base_log();
    let glwe_ds_level = param.glwe_ds_level();
    let common_polynomial_size = param.common_polynomial_size();
    let fft_type_ds = param.fft_type_ds();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type_auto = param.fft_type_auto();
    let ss_base_log = param.ss_base_log();
    let ss_level = param.ss_level();
    let cbs_base_log = param.cbs_base_log();
    let cbs_level = param.cbs_level();
    let log_lut_count = param.log_lut_count();
    let ciphertext_modulus = param.ciphertext_modulus();

    let glwe_size = glwe_dimension.to_glwe_size();

    println!(
"n: {}, N: {}, k: {}, B_pbs: 2^{}, l_pbs: {}, B_cbs: 2^{}, l_cbs: {},
B_glwe_ds: 2^{}, l_glwe_ds: {}, fft_type_ds: {:?},
B_auto: 2^{}, l_auto: {}, fft_type_auto: {:?},
B_ss: 2^{}, l_ss: {}, log_lut_count: {}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_base_log.0, pbs_level.0, cbs_base_log.0, cbs_level.0,
        glwe_ds_base_log.0, glwe_ds_level.0, fft_type_ds,
        auto_base_log.0, auto_level.0, fft_type_auto,
        ss_base_log.0, ss_level.0, log_lut_count.0,
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let (
        lwe_sk,
        glwe_sk,
        lwe_sk_after_ks,
        fourier_bsk,
        fourier_ksk,
    ) = keygen_pbs_with_glwe_ds(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        glwe_ds_base_log,
        glwe_ds_level,
        common_polynomial_size,
        fft_type_ds,
        ciphertext_modulus,
        &mut secret_generator,
        &mut encryption_generator,
    );
    let fourier_bsk = fourier_bsk.as_view();

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
        fft_type_auto,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let mut rng = rand::thread_rng();
    let mut lwe_ks_err_list = vec![];
    let mut sub_err_list = vec![];
    let mut lin_err_list = vec![];
    let mut total_max_err = 0u64;

    // ======== Plain ========
    let mut key = [0u8; BLOCKSIZE_IN_BYTE];
    for i in 0..BLOCKSIZE_IN_BYTE {
        key[i] = rng.gen_range(0..=u8::MAX);
    }

    let aes = Aes128Ref::new(&key);
    let round_keys = aes.get_round_keys();

    let mut message = [0u8; BLOCKSIZE_IN_BYTE];
    for i in 0..16 {
        message[i] = rng.gen_range(0..=255);
    }
    let mut state = byte_array_to_mat(message);

    // ======== HE ========
    let mut he_round_keys = Vec::<LweCiphertextListOwned<u64>>::with_capacity(NUM_ROUNDS + 1);
    for r in 0..=NUM_ROUNDS {
        let mut lwe_list_rk = LweCiphertextList::new(
            0u64,
            fourier_bsk.output_lwe_dimension().to_lwe_size(),
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );

        let rk = PlaintextList::from_container((0..BLOCKSIZE_IN_BIT).map(|i| {
            let byte_idx = i / BYTESIZE;
            let bit_idx = i % BYTESIZE;
            let round_key_byte = round_keys[r][byte_idx];
            let round_key_bit = (round_key_byte & (1 << bit_idx)) >> bit_idx;
            (round_key_bit as u64) << 63
        }).collect::<Vec<u64>>());
        encrypt_lwe_ciphertext_list(
            &lwe_sk,
            &mut lwe_list_rk,
            &rk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        he_round_keys.push(lwe_list_rk);
    }

    let mut he_state = LweCiphertextList::new(
        0u64,
        fourier_bsk.output_lwe_dimension().to_lwe_size(),
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );
    let mut he_state_ks = LweCiphertextList::new(
        0u64,
        lwe_sk_after_ks.lwe_dimension().to_lwe_size(),
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    for (bit_idx, mut he_bit) in he_state.iter_mut().enumerate() {
        let byte_idx = bit_idx / 8;
        let pt = (message[byte_idx] & (1 << bit_idx)) >> bit_idx;
        *he_bit.get_mut_body().data += (pt as u64) << 63;
    }

    // AddRoundKey
    he_add_round_key(&mut he_state, &he_round_keys[0]);
    aes.add_round_key(&mut state, 0);

    for r in 1..NUM_ROUNDS {
        // LWE KS
        for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
            keyswitch_lwe_ciphertext_by_glwe_keyswitch(
                &lwe,
                &mut lwe_ks,
                &fourier_ksk,
            );
        }

        let (_, max_err) = get_he_state_error(&he_state_ks, state, &lwe_sk_after_ks);
        lwe_ks_err_list.push(max_err);
        total_max_err = std::cmp::max(total_max_err, max_err);

        // SubBytes
        he_sub_bytes_by_patched_wwlp_cbs(
            &he_state_ks,
            &mut he_state,
            fourier_bsk,
            &auto_keys,
            ss_key,
            cbs_base_log,
            cbs_level,
            log_lut_count,
        );

        aes.sub_bytes(&mut state);
        let (_, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
        sub_err_list.push(max_err);
        total_max_err = std::cmp::max(total_max_err, max_err);

        // ShiftRows
        he_shift_rows(&mut he_state);

        // MixColumns
        he_mix_columns(&mut he_state);

        // AddRoundKey
        he_add_round_key(&mut he_state, &he_round_keys[r]);

        aes.shift_rows(&mut state);
        aes.mix_columns(&mut state);
        aes.add_round_key(&mut state, r);
        let (_, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
        lin_err_list.push(max_err);
        total_max_err = std::cmp::max(total_max_err, max_err);
    }

    // LWE KS
    for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
        keyswitch_lwe_ciphertext_by_glwe_keyswitch(
            &lwe,
            &mut lwe_ks,
            &fourier_ksk,
        );
    }

    let (_, max_err) = get_he_state_error(&he_state_ks, state, &lwe_sk_after_ks);
    lwe_ks_err_list.push(max_err);
    total_max_err = std::cmp::max(total_max_err, max_err);


    // SubBytes
    he_sub_bytes_by_patched_wwlp_cbs(
        &he_state_ks,
        &mut he_state,
        fourier_bsk,
        &auto_keys,
        ss_key,
        cbs_base_log,
        cbs_level,
        log_lut_count,
    );

    aes.sub_bytes(&mut state);
    let (_, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
    sub_err_list.push(max_err);
    total_max_err = std::cmp::max(total_max_err, max_err);

    // ShiftRows
    he_shift_rows(&mut he_state);

    // AddRoundKey
    he_add_round_key(&mut he_state, &he_round_keys[NUM_ROUNDS]);

    aes.shift_rows(&mut state);
    aes.add_round_key(&mut state, NUM_ROUNDS);
    let (_, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
    lin_err_list.push(max_err);
    total_max_err = std::cmp::max(total_max_err, max_err);

    println!("max {:.2}", (total_max_err as f64).log2());
    println!("x e");
    let mut ctr = 1;
    for ((lwe_ks_err, sub_err), lin_err) in lwe_ks_err_list.iter()
        .zip(sub_err_list.iter())
        .zip(lin_err_list.iter())
    {
        println!("{} {:.2}", ctr, (*lwe_ks_err as f64).log2());
        println!("{} {:.2}", ctr+1, (*sub_err as f64).log2());
        println!("{} {:.2}", ctr+2, (*lin_err as f64).log2());
        ctr += 3;
    }
}
