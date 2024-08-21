use aligned_vec::ABox;
use tfhe::{
    shortint::prelude::*,
    core_crypto::{
        prelude::*,
        fft_impl::fft64::{
            c64,
            crypto::{
                bootstrap::FourierLweBootstrapKeyView,
                ggsw::FourierGgswCiphertextListView,
            },
        },
    },
};
use std::collections::HashMap;
use crate::{aes_ref::*, ggsw_conv::*, utils::*, AutomorphKey};

#[inline]
pub fn he_add_round_key<Scalar, StateCont, RkCont>(
    he_state: &mut LweCiphertextList<StateCont>,
    he_round_key: &LweCiphertextList<RkCont>,
) where
    Scalar: UnsignedInteger,
    StateCont: ContainerMut<Element=Scalar>,
    RkCont: Container<Element=Scalar>,
{
    lwe_ciphertext_list_add_assign(he_state, he_round_key.as_view());
}

pub fn he_sub_bytes_by_patched_wwlp_cbs<Scalar, InputCont, OutputCont>(
    he_state_input: &LweCiphertextList<InputCont>,
    he_state_output: &mut LweCiphertextList<OutputCont>,
    fourier_bsk: FourierLweBootstrapKeyView,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    for (input_byte, mut output_byte) in he_state_input.chunks_exact(BYTESIZE)
        .zip(he_state_output.chunks_exact_mut(BYTESIZE))
    {
        he_sbox_eval_by_patched_wwlp_cbs(
            &input_byte,
            &mut output_byte,
            fourier_bsk,
            auto_keys,
            ss_key,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }
}

fn get_he_state_byte<Scalar, Cont>(
    he_state: &LweCiphertextList<Cont>,
    row: usize,
    col: usize,
) -> LweCiphertextListView<Scalar>
where
    Scalar: UnsignedInteger,
    Cont: Container<Element=Scalar>,
{
    let byte_idx = 4 * col + row;
    he_state.get_sub((8*byte_idx)..(8*byte_idx + 8))
}

fn get_he_state_byte_mut<Scalar, Cont>(
    he_state: &mut LweCiphertextList<Cont>,
    row: usize,
    col: usize,
) -> LweCiphertextListMutView<Scalar>
where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element=Scalar>,
{
    let byte_idx = 4 * col + row;
    he_state.get_sub_mut((8*byte_idx)..(8*byte_idx+8))
}

pub fn he_shift_rows<Scalar, Cont>(he_state: &mut LweCiphertextList<Cont>)
where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element=Scalar>,
{
    let mut buf = LweCiphertextList::new(
        Scalar::ZERO,
        he_state.lwe_size(),
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        he_state.ciphertext_modulus(),
    );
    buf.as_mut().clone_from_slice(he_state.as_ref());

    for row in 1..4 {
        for col in 0..4 {
            let mut dst = get_he_state_byte_mut(he_state, row, col);
            let src = get_he_state_byte(&buf, row, (row + col) % 4);
            dst.as_mut().clone_from_slice(src.as_ref());
        }
    }
}

pub fn he_mix_columns<Scalar, Cont>(he_state: &mut LweCiphertextList<Cont>)
where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element=Scalar>,
{
    let mut buf = LweCiphertextList::new(Scalar::ZERO, he_state.lwe_size(), LweCiphertextCount(BLOCKSIZE_IN_BIT), he_state.ciphertext_modulus());
    buf.as_mut().clone_from_slice(he_state.as_ref());

    for row in 0..4 {
        for col in 0..4 {
            let mut tmp = LweCiphertextList::new(Scalar::ZERO, buf.lwe_size(), LweCiphertextCount(BYTESIZE), buf.ciphertext_modulus());

            tmp.as_mut().clone_from_slice(get_he_state_byte(&buf, row, col).as_ref());
            lwe_ciphertext_list_add_assign(
                &mut tmp,
                get_he_state_byte(&buf, (row + 1) % 4, col),
            );
            he_mult_by_two_assign(&mut tmp);
            lwe_ciphertext_list_add_assign(
                &mut tmp,
                get_he_state_byte(&buf, (row + 1) % 4, col),
            );
            lwe_ciphertext_list_add_assign(
                &mut tmp,
                get_he_state_byte(&buf, (row + 2) % 4, col),
            );
            lwe_ciphertext_list_add_assign(
                &mut tmp,
                get_he_state_byte(&buf, (row + 3) % 4, col),
            );

            get_he_state_byte_mut(he_state, row, col).as_mut().clone_from_slice(tmp.as_ref());
        }
    }
}

fn he_mult_by_two<Scalar, Cont>(he_byte: &LweCiphertextList<Cont>) -> LweCiphertextListOwned<Scalar>
where
    Scalar: UnsignedInteger,
    Cont: Container<Element=Scalar>,
{
    debug_assert!(he_byte.entity_count() == BYTESIZE);

    // 2 * (a7, a6, …, a0)
    // = (a6, a5, …, a0, 0) + (0, 0, 0, a7, a7, 0, a7, a7)
    // = (a6, a5, a4, a3 + a7, a2 + a7, a1, a0 + a7, a7)
    let mut output = LweCiphertextList::new(
        Scalar::ZERO,
        he_byte.lwe_size(),
        LweCiphertextCount(BYTESIZE),
        he_byte.ciphertext_modulus(),
    );

    for i in 1..BYTESIZE {
        output.get_mut(i).as_mut().clone_from_slice(he_byte.get(i-1).as_ref());
    }

    let he_msb = he_byte.get(BYTESIZE-1);
    for i in [0, 1, 3, 4] {
        lwe_ciphertext_add_assign(&mut output.get_mut(i), &he_msb);
    }

    output
}

fn he_mult_by_two_assign<Scalar, Cont>(he_byte: &mut LweCiphertextList<Cont>)
where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element=Scalar>,
{
    let buf = he_mult_by_two(&he_byte);
    he_byte.as_mut().clone_from_slice(buf.as_ref());
}

fn he_sbox_eval_by_patched_wwlp_cbs<Scalar, InCont, OutCont>(
    input: &LweCiphertextList<InCont>,
    output: &mut LweCiphertextList<OutCont>,
    fourier_bsk: FourierLweBootstrapKeyView,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    InCont: Container<Element=Scalar>,
    OutCont: ContainerMut<Element=Scalar>,
{
    let glwe_size = fourier_bsk.glwe_size();
    let polynomial_size = fourier_bsk.polynomial_size();
    let ciphertext_modulus = output.ciphertext_modulus();

    let mut vec_glev = vec![
        GlweCiphertextList::new(
            Scalar::ZERO,
            glwe_size,
            polynomial_size,
            GlweCiphertextCount(ggsw_level.0),
            ciphertext_modulus,
        ); BYTESIZE];
    for (input_bit, glev) in input.iter().zip(vec_glev.iter_mut()) {
        let glev_mut_view = GlweCiphertextListMutView::from_container(
            glev.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );

        lwe_msb_bit_to_glev_by_trace_with_preprocessing(
            input_bit.as_view(),
            glev_mut_view,
            fourier_bsk,
            auto_keys,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }

    let mut ggsw_bit_list = GgswCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
        GgswCiphertextCount(vec_glev.len()),
        ciphertext_modulus,
    );
    for (mut ggsw, glev) in ggsw_bit_list.iter_mut().zip(vec_glev.iter()) {
        switch_scheme(&glev, &mut ggsw, ss_key);
    }

    let mut fourier_ggsw_bit_list = FourierGgswCiphertextList::new(
        vec![c64::default();
        BYTESIZE * polynomial_size.to_fourier_polynomial_size().0
            * glwe_size.0
            * glwe_size.0
            * ggsw_level.0
        ],
        BYTESIZE,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
    );
    for (mut fourier_ggsw, ggsw) in fourier_ggsw_bit_list.as_mut_view().into_ggsw_iter().zip(ggsw_bit_list.iter()) {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }

    let num_par_lut = polynomial_size.0 / (1 << BYTESIZE);
    let num_accumulator = if BYTESIZE % num_par_lut == 0 {
        BYTESIZE / num_par_lut
    } else {
        BYTESIZE / num_par_lut + 1
    };

    for acc_idx in 0..num_accumulator {
        let accumulator = (0..polynomial_size.0).map(|i| {
            let lut_idx = acc_idx * num_par_lut + i / (1 << BYTESIZE);
            (((AES128_SBOX[i % (1 << BYTESIZE)] & (1 << lut_idx)) as usize) << ((Scalar::BITS - 1) - lut_idx)).cast_into()
        }).collect::<Vec<Scalar>>();
        let accumulator_plaintext = PlaintextList::from_container(accumulator);
        let mut accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext, ciphertext_modulus);

        for (i, fourier_ggsw_bit) in fourier_ggsw_bit_list.as_view().into_ggsw_iter().into_iter().enumerate() {
            let mut buf = accumulator.clone();
            glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(1 << i));
            glwe_ciphertext_sub_assign(&mut buf, &accumulator);
            add_external_product_assign(&mut accumulator, &fourier_ggsw_bit, &buf);
        }

        for i in 0..num_par_lut {
            let bit_idx = acc_idx * num_par_lut + i;
            let mut lwe_out = output.get_mut(bit_idx);
            extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut lwe_out, MonomialDegree(i * (1 << BYTESIZE)));
        }
    }
}


pub fn get_he_state_error<Scalar, StateCont, SkCont>(
    he_state: &LweCiphertextList<StateCont>,
    plain_state: StateByteMat,
    lwe_sk: &LweSecretKey<SkCont>,
) -> (Vec::<usize>, Scalar)
where
    Scalar: UnsignedInteger + CastFrom<u8>,
    StateCont: Container<Element=Scalar>,
    SkCont: Container<Element=Scalar>,
{
    let plain_state = byte_mat_to_bit_array(plain_state);
    let mut vec_err = Vec::<usize>::with_capacity(BLOCKSIZE_IN_BIT);
    let mut max_err = Scalar::ZERO;

    for (correct_val, he_bit) in plain_state.iter().zip(he_state.iter()) {
        let correct_val = Scalar::cast_from(*correct_val);
        let (_decoded, bit_err, abs_err) = get_val_and_bit_and_abs_err(
            lwe_sk,
            &he_bit,
            correct_val,
            Scalar::ONE << (Scalar::BITS - 1),
        );
        vec_err.push(bit_err as usize);
        max_err = std::cmp::max(max_err, abs_err);
    }

    (vec_err, max_err)
}
