# Patching and Extending the WWL+ Circuit Bootstrapping Method to FFT Domains
This is an implementation of ['Patching and Extending the WWL+ Circuit Bootstrapping Method to FFT Domains'](https://eprint.iacr.org/archive/2024/1318/20240902:055949).


## Contents
We implement:
- tests for
  - GLWE keyswitching by the split FFT ([`glwe_keyswitch`](tests/glwe_keyswitch.rs))
  - automorphism-based LWE to GLWE conversion ([`lwe_to_glwe`](tests/lwe_to_glwe.rs) and [`lwe_to_glwe_with_dim_switch`](tests/lwe_to_glwe_with_dim_switch.rs))
  - LWE keyswitching by GLWE dimension switching ([`lwe_ks_by_glwe_ds`](tests/lwe_ks_by_glwe_ds.rs))
  - AES reference implementation and TFHE evaluation ([`aes_ref`](tests/aes_ref.rs) and [`aes_eval`](tests/aes_eval.rs))
  - sampling errors ([`sample_lwe_to_glwe_err`](tests/sample_lwe_to_glwe_err.rs), [`sample_ggsw_conv_err`](tests/sample_ggsw_conv_err.rs), [`sample_cbs_err`](tests/sample_cbs_err.rs), [`sample_aes_eval_err`](tests/sample_aes_eval_err.rs))
- benchmarks for
  - LWE to GLWE conversion methods ([`bench_lwe_to_glwe`](benches/bench_lwe_to_glwe.rs))
  - improved WoP-PBS ([`bench_cbs`](benches/bench_cbs.rs))
  - AES evaluation ([`bench_aes`](benches/bench_aes.rs))
- error analysis for
  - improved WoP-PBS
  - AES evaluation (by our improved WoP-PBS)
  - AES evaluation (by the original WWL+ method)

## How to use
- tests: `cargo test --release --test 'test_name'`
- bench: `cargo bench --bench 'benchmark_name'`
  - Current sample size is set to 1000. It can be changed by modifying `config = Criterion::default().sample_size(1000);`
- error analysis: `sage err_analysis.sage`
