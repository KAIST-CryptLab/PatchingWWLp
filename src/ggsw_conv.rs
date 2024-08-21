use std::collections::HashMap;
use aligned_vec::{ABox, CACHELINE_ALIGN};
use tfhe::core_crypto::{
    fft_impl::fft64::{
        c64,
        crypto::{
            bootstrap::FourierLweBootstrapKeyView, ggsw::FourierGgswCiphertextListView
        },
    }, prelude::{polynomial_algorithms::*, *}
};
use crate::{automorphism::*, glwe_conv::*, lwe_preprocessing_assign, pbs::*, utils::*};

pub fn generate_scheme_switching_key<Scalar, G>(
    glwe_secret_key: &GlweSecretKeyOwned<Scalar>,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<G>,
) -> FourierGgswCiphertextList<Vec<c64>>
where
    Scalar: UnsignedTorus,
    G: ByteRandomGenerator,
{
    let glwe_dimension = glwe_secret_key.glwe_dimension();
    let glwe_size = glwe_dimension.to_glwe_size();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let glwe_sk_poly_list = glwe_secret_key.as_polynomial_list();

    let mut ggsw_key = GgswCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        ss_base_log,
        ss_level,
        GgswCiphertextCount(glwe_dimension.0),
        ciphertext_modulus,
    );
    for mut ggsw in ggsw_key.iter_mut() {
        encrypt_constant_ggsw_ciphertext(
            glwe_secret_key,
            &mut ggsw,
            Plaintext(Scalar::ZERO),
            noise_parameters,
            generator,
        );
    }

    for (i, mut ggsw) in ggsw_key.iter_mut().enumerate() {
        let glwe_sk_poly_i = glwe_sk_poly_list.get(i);
        for (row, mut glwe) in ggsw.as_mut_glwe_list().iter_mut().enumerate() {
            let k = row / glwe_size.0;
            let log_scale = Scalar::BITS - (k + 1) * ss_base_log.0;

            let mut buf = Polynomial::new(Scalar::ZERO, polynomial_size);
            for (elem, sk) in buf.iter_mut().zip(glwe_sk_poly_i.iter()) {
                *elem = (*sk).wrapping_neg() << log_scale;
            }

            let col = row % glwe_size.0;
            if col < glwe_dimension.0 {
                let mut mask = glwe.get_mut_mask();
                let mut mask = mask.as_mut_polynomial_list();
                let mut mask = mask.get_mut(col);
                polynomial_wrapping_add_assign(&mut mask, &buf);
            } else {
                let mut body = glwe.get_mut_body();
                let mut body = body.as_mut_polynomial();
                polynomial_wrapping_add_assign(&mut body, &buf);
            }
        }
    }

    let mut fourier_ggsw_key = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            glwe_dimension.0 * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * ss_level.0
        ],
        glwe_dimension.0,
        glwe_size,
        polynomial_size,
        ss_base_log,
        ss_level,
    );

    for (mut fourier_ggsw, ggsw) in fourier_ggsw_key.as_mut_view().into_ggsw_iter().zip(ggsw_key.iter()) {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }

    fourier_ggsw_key
}


pub fn switch_scheme<Scalar, InputCont, OutputCont>(
    glev: &GlweCiphertextList<InputCont>,
    ggsw: &mut GgswCiphertext<OutputCont>,
    ss_key: FourierGgswCiphertextListView,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    assert_eq!(glev.ciphertext_modulus(), ggsw.ciphertext_modulus());
    assert_eq!(glev.polynomial_size(), ggsw.polynomial_size());
    assert_eq!(glev.polynomial_size(), ss_key.polynomial_size());
    assert_eq!(glev.glwe_size(), ggsw.glwe_size());
    assert_eq!(glev.glwe_size(), ss_key.glwe_size());
    assert_eq!(glev.glwe_ciphertext_count().0, ggsw.decomposition_level_count().0);

    ggsw.as_mut().fill(Scalar::ZERO);

    let glwe_size = glev.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();

    for (col, mut glwe_list) in ggsw.as_mut_glwe_list().chunks_exact_mut(glwe_size.0).enumerate() {
        let glwe_bit = glev.get(col);
        let (mut glwe_mask_list, mut glwe_body_list) = glwe_list.split_at_mut(glwe_dimension.0);

        for (mut glwe_mask, ss_key_ggsw) in glwe_mask_list.iter_mut().zip(ss_key.into_ggsw_iter()) {
            add_external_product_assign(&mut glwe_mask, &ss_key_ggsw, &glwe_bit);
        }
        glwe_ciphertext_clone_from(&mut glwe_body_list.get_mut(0), &glwe_bit);
    }
}

pub fn lwe_msb_bit_to_ggsw_by_pfpks<Scalar, InputCont, OutputCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut GgswCiphertext<OutputCont>,
    fourier_bsk: FourierLweBootstrapKeyView,
    pfpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<KeyCont>,
    log_lut_count: LutCountLog,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
    KeyCont: Container<Element=Scalar>,
{
    assert_eq!(input.lwe_size(), fourier_bsk.input_lwe_dimension().to_lwe_size());
    assert_eq!(input.ciphertext_modulus(), output.ciphertext_modulus());

    let ggsw_base_log = output.decomposition_base_log();
    let ggsw_level = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    let lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();
    let mut lev = LweCiphertextList::new(Scalar::ZERO, lwe_size, LweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    lwe_msb_bit_to_lev(input, &mut lev, fourier_bsk, ggsw_base_log, ggsw_level, log_lut_count);

    for (lwe, mut ggsw_level_matrix) in lev.iter().zip(output.iter_mut()) {
        for (pfpksk, mut glwe) in pfpksk_list.iter()
            .zip(ggsw_level_matrix.as_mut_glwe_list().iter_mut())
        {
            private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                &pfpksk,
                &mut glwe,
                &lwe,
            );
        }
    }
}

pub fn lwe_msb_bit_to_glev_by_trace_with_preprocessing<Scalar>(
    lwe_in: LweCiphertextView<Scalar>,
    mut glev: GlweCiphertextListMutView<Scalar>,
    fourier_bsk: FourierLweBootstrapKeyView,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    glev_base_log: DecompositionBaseLog,
    glev_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u128>,
{
    assert_eq!(lwe_in.lwe_size(), fourier_bsk.input_lwe_dimension().to_lwe_size());
    assert_eq!(glev.entity_count(), glev_level.0);

    let glwe_size = fourier_bsk.glwe_size();
    let polynomial_size = fourier_bsk.polynomial_size();
    let half_box_size = polynomial_size.0 / 2;
    let ciphertext_modulus = lwe_in.ciphertext_modulus();

    let lut_count = 1 << log_lut_count.0;
    for (acc_idx, mut glev_chunk) in glev.chunks_mut(lut_count).enumerate() {
        let mut accumulator = (0..polynomial_size.0).map(|i| {
            let k = i % lut_count;
            let log_scale = Scalar::BITS - (acc_idx * lut_count + k + 1) * glev_base_log.0;
            (Scalar::ONE).wrapping_neg() << (log_scale - 1)
        }).collect::<Vec<Scalar>>();

        for a_i in accumulator[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }
        accumulator.rotate_left(half_box_size);

        let accumulator_plaintext = PlaintextList::from_container(accumulator);
        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &accumulator_plaintext,
            ciphertext_modulus,
        );

        let mut buffers = ComputationBuffers::new();
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                glwe_size,
                polynomial_size,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = buffers.stack();

        let (mut local_accumulator_data, stack) = stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
        let mut local_accumulator = GlweCiphertextMutView::from_container(
            &mut *local_accumulator_data,
            polynomial_size,
            ciphertext_modulus,
        );

        gen_blind_rotate_local_assign(
            fourier_bsk,
            local_accumulator.as_mut_view(),
            ModulusSwitchOffset(0),
            log_lut_count,
            lwe_in.as_ref(),
            fft,
            stack,
        );

        let mut buf_glwe = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
        let mut buf_lwe = LweCiphertext::new(Scalar::ZERO, fourier_bsk.output_lwe_dimension().to_lwe_size(), ciphertext_modulus);
        for (k, mut glwe) in glev_chunk.iter_mut().enumerate() {
            let cur_level = acc_idx * lut_count + k + 1;
            let log_scale = Scalar::BITS - cur_level * glev_base_log.0;

            glwe_ciphertext_clone_from(&mut buf_glwe, &local_accumulator);
            glwe_ciphertext_monic_monomial_div_assign(&mut buf_glwe, MonomialDegree(k));
            glwe_ciphertext_plaintext_add_assign(&mut buf_glwe, Plaintext(Scalar::ONE << (log_scale - 1)));

            extract_lwe_sample_from_glwe_ciphertext(&buf_glwe, &mut buf_lwe, MonomialDegree(0));
            lwe_preprocessing_assign(&mut buf_lwe, polynomial_size);
            convert_lwe_to_glwe_const(&buf_lwe, &mut glwe);
            trace_assign(&mut glwe, &auto_keys);
        }
    }
}


pub fn lwe_msb_bit_to_glev_by_pksk<Scalar>(
    lwe_in: LweCiphertextView<Scalar>,
    mut glev: GlweCiphertextListMutView<Scalar>,
    fourier_bsk: FourierLweBootstrapKeyView,
    pksk: &LwePackingKeyswitchKeyView<Scalar>,
    glev_base_log: DecompositionBaseLog,
    glev_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u128>,
{
    assert_eq!(lwe_in.lwe_size(), fourier_bsk.input_lwe_dimension().to_lwe_size());
    assert_eq!(glev.entity_count(), glev_level.0);

    let glwe_size = fourier_bsk.glwe_size();
    let polynomial_size = fourier_bsk.polynomial_size();
    let half_box_size = polynomial_size.0 / 2;
    let ciphertext_modulus = lwe_in.ciphertext_modulus();

    let lut_count = 1 << log_lut_count.0;
    for (acc_idx, mut glev_chunk) in glev.chunks_mut(lut_count).enumerate() {
        let mut accumulator = (0..polynomial_size.0).map(|i| {
            let k = i % lut_count;
            let log_scale = Scalar::BITS - (acc_idx * lut_count + k + 1) * glev_base_log.0;
            (Scalar::ONE).wrapping_neg() << (log_scale - 1)
        }).collect::<Vec<Scalar>>();

        for a_i in accumulator[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }
        accumulator.rotate_left(half_box_size);

        let accumulator_plaintext = PlaintextList::from_container(accumulator);
        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &accumulator_plaintext,
            ciphertext_modulus,
        );

        let mut buffers = ComputationBuffers::new();
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                glwe_size,
                polynomial_size,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = buffers.stack();

        let (mut local_accumulator_data, stack) = stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
        let mut local_accumulator = GlweCiphertextMutView::from_container(
            &mut *local_accumulator_data,
            polynomial_size,
            ciphertext_modulus,
        );

        gen_blind_rotate_local_assign(
            fourier_bsk,
            local_accumulator.as_mut_view(),
            ModulusSwitchOffset(0),
            log_lut_count,
            lwe_in.as_ref(),
            fft,
            stack,
        );

        for (k, mut glwe) in glev_chunk.iter_mut().enumerate() {
            let cur_level = acc_idx * lut_count + k + 1;
            let log_scale = Scalar::BITS - cur_level * glev_base_log.0;

            let mut buf = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
            glwe_ciphertext_clone_from(&mut buf, &local_accumulator);
            glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(k));
            glwe_ciphertext_plaintext_add_assign(&mut buf, Plaintext(Scalar::ONE << (log_scale - 1)));

            let mut lwe_out = LweCiphertext::new(Scalar::ZERO, fourier_bsk.output_lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&buf, &mut lwe_out, MonomialDegree(0));
            keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pksk, &lwe_out, &mut glwe);
        }
    }
}


pub fn circuit_bootstrap_lwe_ciphertext_by_trace_with_preprocessing<Scalar>(
    lwe_in: LweCiphertextView<Scalar>,
    fourier_bsk: FourierLweBootstrapKeyView,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) -> FourierGgswCiphertext<ABox<[c64]>>
where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u128>
{
    assert!(fourier_bsk.polynomial_size() == ss_key.polynomial_size());
    assert!(fourier_bsk.glwe_size() == ss_key.glwe_size());
    assert!(lwe_in.ciphertext_modulus().is_native_modulus());

    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();
    let ciphertext_modulus = lwe_in.ciphertext_modulus();

    let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    let glev_mut_view = GlweCiphertextListMutView::from_container(glev.as_mut(), glwe_size, polynomial_size, ciphertext_modulus);

    lwe_msb_bit_to_glev_by_trace_with_preprocessing(lwe_in.as_view(), glev_mut_view, fourier_bsk, auto_keys, ggsw_base_log, ggsw_level, log_lut_count);

    let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);
    switch_scheme(&glev, &mut ggsw, ss_key);

    let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, ggsw_base_log, ggsw_level);
    convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);

    fourier_ggsw
}


pub fn circuit_bootstrap_lwe_ciphertext_by_pksk<Scalar>(
    lwe_in: LweCiphertextView<Scalar>,
    fourier_bsk: FourierLweBootstrapKeyView,
    pksk: &LwePackingKeyswitchKeyView<Scalar>,
    ss_key: FourierGgswCiphertextListView,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) -> FourierGgswCiphertext<ABox<[c64]>>
where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u128>
{
    assert!(fourier_bsk.polynomial_size() == ss_key.polynomial_size());
    assert!(fourier_bsk.glwe_size() == ss_key.glwe_size());
    assert!(lwe_in.ciphertext_modulus().is_native_modulus());

    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();
    let ciphertext_modulus = lwe_in.ciphertext_modulus();

    let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    let glev_mut_view = GlweCiphertextListMutView::from_container(glev.as_mut(), glwe_size, polynomial_size, ciphertext_modulus);

    lwe_msb_bit_to_glev_by_pksk(lwe_in.as_view(), glev_mut_view, fourier_bsk, pksk, ggsw_base_log, ggsw_level, log_lut_count);

    let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);
    switch_scheme(&glev, &mut ggsw, ss_key);

    let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, ggsw_base_log, ggsw_level);
    convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);

    fourier_ggsw
}

