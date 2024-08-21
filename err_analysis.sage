def get_var_pbs(N, k, n, Var_GLWE, q, B_pbs, l_pbs):
    Var_BSK = Var_GLWE * q^2

    Var_PBS = 0
    Var_PBS += n * l_pbs * (k + 1) * N * (B_pbs^2 + 2) / 12 * Var_BSK
    Var_PBS += n * (q^2 - B_pbs^(2*l_pbs)) / (24 * B_pbs^(2*l_pbs)) * (1 + k*N/2)
    Var_PBS += n*k*N/32
    Var_PBS += n/16 * (1 - k*N/2)^2

    return Var_PBS

def get_var_glwe_ks(N, k_src, Var_dst, q, B_ksk, l_ksk):
    Var_KSK = Var_dst * q^2

    Var_KS = 0
    # Var_KS += k_src * N * l_ksk * Var_KSK * (B_ksk^2/12 + 1/6)
    # Var_KS += k_src * N / 24 * (q^2/B_ksk^(2*l_ksk) + 1/2)
    Var_KS += k_src * N * l_ksk * Var_KSK * (B_ksk / 2)^2
    Var_KS += k_src * N / 12 * (q^2 / (B_ksk^(2 * l_ksk)) - 1)

    return Var_KS

def get_var_lwe_ks(k, N, Var_LWE, q, B_ksk, l_ksk):
    Var_KSK = Var_LWE * q^2

    Var_KS = 0
    Var_KS += k * N * l_ksk * Var_KSK * (B_ksk^2/12 + 1/6)
    Var_KS += k * N / 24 * (q^2 / (B_ksk^(2*l_ksk)) + 1 / 2)

    return Var_KS

def get_gamma(n, N, q, theta, delta_in, Var_in):
    w = 2*N*2^(-theta)

    Var = 0
    Var += (w/q)^2 * (Var_in - 1/12)
    Var += n/48 * ((w/q)^2 + 2)
    Var += 1/12

    return w * delta_in / (2 * q * Var^(1/2))

def get_fail_prob(Gamma):
    return 1 - erf(Gamma / 2^(1/2))


print("======== WoP-PBS PBSmanyLUT Failure Probability ========")
wopbs_2_2 = (
    "WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS",
    769, # n
    2048, # N
    1, # k
    0.0000043131554647504185^2, # LWE var
    0.00000000000000029403601535432533^2, # GLWE var
    2^23, # refresh base
    1, # refresh level
    2^6, # KS base
    2, # KS level
    2, # theta
)

wopbs_3_3 = (
    "WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS",
    873, # n
    2048, # N
    1, # k
    0.0000006428797112843789^2, # LWE var
    0.00000000000000029403601535432533^2, # GLWE var
    2^23, # refresh base
    1, # refresh level
    2^10, # KS base
    1, # KS level
    2, # theta
)

wopbs_4_4 = (
    "WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS",
    953, # n
    2048, # N
    1, # k
    0.0000001486733969411098^2, # LWE var
    0.00000000000000029403601535432533^2, # GLWE var
    2^23, # refresh base
    1, # refresh level
    2^11, # KS base
    1, # KS level
    3, # theta
)

param_list = [
    wopbs_2_2,
    wopbs_3_3,
    wopbs_4_4,
]

for param in param_list:
    name = param[0]
    n = param[1]
    N = param[2]
    k = param[3]
    Var_LWE = param[4]
    Var_GLWE = param[5]
    B_refresh = param[6]
    l_refresh = param[7]
    B_ks = param[8]
    l_ks = param[9]
    theta = param[10]

    print(name)
    print(f"n: {n}, N: {N}, k: {k}, B_refresh: 2^{log(B_refresh, 2)}, l_refresh: {l_refresh}, B_ks: 2^{log(B_ks, 2)}, l_ks: {l_ks}, theta: {theta}\n")

    Var_refresh = get_var_pbs(N, k, n, Var_GLWE, 2^64, B_refresh, l_refresh)
    Var_KS = get_var_lwe_ks(k, N, Var_LWE, 2^64, B_ks, l_ks)
    Var_in = Var_refresh + Var_KS

    print(f"- Var_refresh: 2^{log(Var_refresh, 2).n()}")
    print(f"- Var_ks     : 2^{log(Var_KS, 2).n()}")
    print(f"- Var_in     : 2^{log(Var_in, 2).n()}")

    Gamma = get_gamma(n, N, 2^64, theta, 2^63, Var_in)
    prob = get_fail_prob(Gamma)

    print()
    print(f"- Gamma: {Gamma}")
    print(f"- Failure Prob: 2^{log(prob, 2).n(1000):.10}")
    print()
    print()


print("======== AES Failure Probability ========")
set1 = (
    "Set-I",
    768, # n
    2048, # N
    1, # k
    0.00000702047462940120^2, # LWE var
    0.00000000000000029403601535432533^2, # GLWE var
    2^4, # DS base
    3, # DS level
    2, # theta
)

set2 = (
    "Set-II",
    768, # n
    1024, # N
    2, # k
    0.00000702047462940120^2, # LWE var
    0.00000000000000029403601535432533^2, # GLWE var
    2^4, # DS base
    3, # DS level
    2, # theta
)

set3 = (
    "Set-III",
    768, # n
    512, # N
    4, # k
    0.00000702047462940120^2, # LWE var
    0.00000000000000029403601535432533^2, # GLWE var
    2^4, # DS base
    3, # DS level
    2, # theta
)

param_list = [
    set1,
    set2,
    set3,
]

for param in param_list:
    name = param[0]
    n = param[1]
    N = param[2]
    k = param[3]
    Var_LWE = param[4]
    Var_GLWE = param[5]
    B_ds = param[6]
    l_ds = param[7]
    theta = param[8]

    print(name)
    print(f"n: {n}, N: {N}, k: {k}, B_ds: 2^{log(B_ds, 2)}, l_ds: {l_ds}, theta: {theta}\n")

    N_common = 256
    k_src = (k * N) // N_common
    Var_KS = get_var_glwe_ks(N_common, k_src, Var_LWE, 2^64, B_ds, l_ds)
    Var_in = 2 * Var_KS

    print(f"- Var_ks: 2^{log(Var_KS, 2).n()}")
    print(f"- Var_in: 2^{log(Var_in, 2).n()}")

    Gamma = get_gamma(n, N, 2^64, theta, 2^63, Var_in)
    prob = get_fail_prob(Gamma)
    prob_aes = prob * 1280

    print()
    print(f"- Gamma: {Gamma}")
    print(f"- PBSmanyLUT Failure Prob: 2^{log(prob, 2).n(1000):.10}")
    print(f"- AES Failure Prob: 2^{log(prob_aes, 2).n(1000):.10}")
    print()
    print()


print("======== WWL+ AES Failure Probability ========")
Q = 2^54
q = 1024
N = 2048
n = 571
sigma = 3.2

l_pbs = 1
B_pbs = 2^26
e_pbs = Q / (2 * B_pbs^l_pbs)

l_cbs = 2
B_cbs = 2^5
e_cbs = Q / (2 * B_cbs^l_cbs)

print(f"n: {n}, q: 2^{log(q, 2)}, N: {N}, Q: 2^{log(Q, 2)}, B_pbs: 2^{log(B_pbs, 2)}, l_pbs: {l_pbs}, B_cbs: 2^{log(B_cbs, 2)}, l_cbs: {l_cbs}\n")

Var_pbs = 0
Var_pbs += N * l_pbs * B_pbs^2 / 6 * sigma^2
Var_pbs += (N + 1) * e_pbs^2 / 3
Var_pbs *= 2 * n

Var_add = 0
Var_add += N * l_cbs * B_cbs^2 / 12 * Var_pbs
Var_add += (N + 1) * e_cbs^2 / 6

print(f"- Var_pbs : 2^{log(Var_pbs, 2).n()}")
print(f"- Var_ggsw: 2^{log(Var_pbs, 2).n()}")
print(f"- Var_add : 2^{log(Var_add, 2).n()}")
print()

for t in [8, 56]:
    print(f"t = {t}")
    Var = 0
    Var += (2*N / Q)^2 * (t * Var_add)
    Var += (n/2 + 1) * (2^(2*theta)/12 - N^2 / (3*q^2))
    Var += n * N^2 / (4 * q^2)

    prob = 1 - erf(2 * N / (4 * (2 * Var)^(1/2)))
    print(f"- Var: 2^{log(Var, 2).n()}")
    print(f"- Failure Prob: 2^{log(prob, 2).n()}")
    print()

