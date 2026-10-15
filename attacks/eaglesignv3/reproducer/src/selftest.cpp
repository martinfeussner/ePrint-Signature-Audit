#include "public_scheme.hpp"

using namespace esv3;

int main() {
  try {
    Poly a(N), b(N);
    for (int i = 0; i < N; ++i) {
      a[i] = (17 * i * i + 31 * i + 7) % Q;
      b[i] = centered((13 * i + 5) % 101 - 50);
    }
    const Poly roundtrip = ntt().inverse(ntt().forward(a));
    for (int i = 0; i < N; ++i) {
      if (mod_q(roundtrip[i]) != mod_q(a[i])) fail("NTT roundtrip failed");
    }
    Poly expected(N, 0);
    for (int i = 0; i < N; ++i) {
      for (int j = 0; j < N; ++j) {
        const int k = i + j;
        if (k < N) {
          expected[k] = mod_q(std::int64_t(expected[k]) +
                              std::int64_t(a[i]) * b[j]);
        } else {
          expected[k - N] = mod_q(std::int64_t(expected[k - N]) -
                                  std::int64_t(a[i]) * b[j]);
        }
      }
    }
    const Poly got = poly_mul(a, b);
    if (got != expected) fail("negacyclic multiplication failed");

    for (int x = -HALF_Q; x <= HALF_Q; ++x) {
      const int lo = low_bits(mod_q(x));
      const int hi = high_bits(mod_q(x));
      if (x != lo + ALPHA * hi) fail("decomposition failed");
      if (lo <= -GAMMA2 || lo > GAMMA2) fail("low-bit range failed");
    }
    if (high_bits(mod_q(-HALF_Q)) != -1 ||
        high_bits(mod_q(HALF_Q)) != 1) {
      fail("edge high bits failed");
    }

    const Bytes mu = shake256({bytes_of("selftest mu")}, 48);
    const Digest64 r = digest64(shake256({bytes_of("selftest r")}, 64));
    const Poly c = challenge(mu, r);
    int weight = 0;
    for (int x : c) {
      if (x != 0) ++weight;
      if (x < -1 || x > 1) fail("challenge coefficient failed");
    }
    if (weight != TAU) fail("challenge weight failed");
    std::cout << "SELFTEST: PASS\n";
    std::cout << "n=" << N << " q=" << Q << " psi=" << ntt().psi << "\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "SELFTEST: FAIL: " << e.what() << "\n";
    return 1;
  }
}

