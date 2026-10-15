#pragma once

#include "public_scheme.hpp"

#include <filesystem>

namespace esv3 {

struct SecretKey {
  PublicKey pk;
  Digest32 tr{};
  Digest32 deterministic_key{};
  Digest32 oracle_seed{};
  Poly d;
  Poly g;
  std::uint32_t key_attempt = 0;
  std::uint32_t g_rehashes = 0;
};

inline Bytes slice(const Bytes &in, std::size_t off, std::size_t len) {
  if (off + len > in.size()) fail("slice out of range");
  return Bytes(in.begin() + static_cast<std::ptrdiff_t>(off),
               in.begin() + static_cast<std::ptrdiff_t>(off + len));
}

inline Bytes u32le(unsigned x) {
  return Bytes{static_cast<std::uint8_t>(x & 0xff),
               static_cast<std::uint8_t>((x >> 8) & 0xff),
               static_cast<std::uint8_t>((x >> 16) & 0xff),
               static_cast<std::uint8_t>((x >> 24) & 0xff)};
}

inline Poly sample_ternary(const Bytes &seed, unsigned nonce) {
  ByteStream xof(shake256({seed, u16le(nonce)}, 8192));
  Poly out;
  out.reserve(N);
  while (static_cast<int>(out.size()) < N) {
    const unsigned x = xof.byte();
    if (x >= 252) continue;
    out.push_back(static_cast<int>(x % 3) - 1);
  }
  return out;
}

inline Poly sample_y(const Bytes &lambda, unsigned k) {
  if (lambda.size() != 48) fail("lambda must follow Appendix A.4's 48-byte profile");
  ByteStream xof(shake256({lambda, u16le(k)}, 16384));
  Poly y;
  y.reserve(N);
  while (static_cast<int>(y.size()) < N) {
    const unsigned x = xof.u16();
    if (x > 2u * GAMMA1) continue;
    y.push_back(static_cast<int>(x) - GAMMA1);
  }
  return y;
}

inline SecretKey generate_key_attempt(const Bytes &target_seed,
                                      std::uint32_t attempt) {
  const Bytes beta = shake256(
      {bytes_of("EagleSignV3 public reproducer target key beta"),
       target_seed, u32le(attempt)}, 32);
  const Bytes expanded = shake256({beta}, 128);
  Bytes beta1 = slice(expanded, 0, 32);
  const Bytes beta2 = slice(expanded, 32, 32);
  const Bytes rho_b = slice(expanded, 64, 32);
  const Bytes key_b = slice(expanded, 96, 32);

  SecretKey sk;
  sk.key_attempt = attempt;
  sk.pk.rho = digest32(rho_b);
  sk.deterministic_key = digest32(key_b);
  sk.oracle_seed = digest32(shake256(
      {bytes_of("EagleSignV3 public reproducer oracle randomness"),
       target_seed, u32le(attempt)},
      32));

  beta1 = shake256({beta1}, 32);  // Algorithm 4, step 3.
  for (;;) {
    sk.g = sample_ternary(beta1, 0);
    if (poly_is_unit(sk.g)) break;
    beta1 = shake256({beta1}, 32);
    ++sk.g_rehashes;
  }
  sk.d = sample_ternary(beta2, 0);

  const Poly a = expand_a(sk.pk.rho);
  Poly a_plus_d(N);
  for (int i = 0; i < N; ++i) a_plus_d[i] = mod_q(a[i] + sk.d[i]);
  sk.pk.t = poly_mul(a_plus_d, poly_inverse(sk.g));
  sk.tr = compute_tr(sk.pk);
  return sk;
}

inline void write_secret_key(const std::string &path, const SecretKey &sk) {
  std::ofstream out(path, std::ios::binary);
  if (!out) fail("cannot create secret key: " + path);
  write_magic(out, {'E', 'S', 'V', '3', 'S', 'K', '1', '\0'});
  write_digest(out, sk.pk.rho);
  for (int x : sk.pk.t) write_u16(out, static_cast<std::uint16_t>(mod_q(x)));
  write_digest(out, sk.tr);
  write_digest(out, sk.deterministic_key);
  write_digest(out, sk.oracle_seed);
  write_u32(out, sk.key_attempt);
  write_u32(out, sk.g_rehashes);
  for (int x : sk.d) {
    if (x < -1 || x > 1) fail("nonternary D in secret key");
    out.put(static_cast<char>(static_cast<std::int8_t>(x)));
  }
  for (int x : sk.g) {
    if (x < -1 || x > 1) fail("nonternary G in secret key");
    out.put(static_cast<char>(static_cast<std::int8_t>(x)));
  }
  if (!out) fail("failed writing secret key");
}

inline SecretKey read_secret_key(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail("cannot open secret key: " + path);
  expect_magic(in, {'E', 'S', 'V', '3', 'S', 'K', '1', '\0'});
  SecretKey sk;
  sk.pk.rho = read_digest32(in);
  sk.pk.t.resize(N);
  for (int &x : sk.pk.t) {
    x = read_u16(in);
    if (x >= Q) fail("noncanonical T in secret key");
  }
  sk.tr = read_digest32(in);
  sk.deterministic_key = read_digest32(in);
  sk.oracle_seed = read_digest32(in);
  sk.key_attempt = read_u32(in);
  sk.g_rehashes = read_u32(in);
  sk.d.resize(N);
  sk.g.resize(N);
  for (int &x : sk.d) {
    const int c = in.get();
    if (c == EOF) fail("EOF reading D");
    x = static_cast<std::int8_t>(static_cast<unsigned char>(c));
    if (x < -1 || x > 1) fail("nonternary D encoding");
  }
  for (int &x : sk.g) {
    const int c = in.get();
    if (c == EOF) fail("EOF reading G");
    x = static_cast<std::int8_t>(static_cast<unsigned char>(c));
    if (x < -1 || x > 1) fail("nonternary G encoding");
  }
  if (in.peek() != EOF) fail("trailing secret-key data");
  if (!digest_equal(sk.tr, compute_tr(sk.pk))) fail("secret-key tr mismatch");
  if (!public_relation_holds(sk.pk, sk.d, sk.g)) fail("secret-key relation failure");
  return sk;
}

struct SignResult {
  Signature signature;
  std::uint32_t internal_attempts = 0;
};

inline SignResult sign_with_lambda(const PublicKey &pk, const Poly &d,
                                   const Poly &g, const Bytes &message,
                                   const Bytes &lambda,
                                   const Poly *precomputed_t_hat = nullptr) {
  const Digest32 tr = compute_tr(pk);
  const Bytes mu = compute_mu(tr, message);
  const Poly local_t_hat = precomputed_t_hat ? Poly{} : ntt().forward(pk.t);
  const Poly &t_hat = precomputed_t_hat ? *precomputed_t_hat : local_t_hat;
  for (unsigned k = 0; k <= 65535; ++k) {
    const Poly y = sample_y(lambda, k);
    const Poly p = poly_mul_pretransformed(t_hat, y);
    const Digest64 r = hash_highbits(high_bits_poly(p));
    const Poly c = challenge(mu, r);
    const Poly gc = sparse_mul(g, c);
    const Poly dc = sparse_mul(d, c);
    Poly z(N), p_plus_dc(N);
    for (int i = 0; i < N; ++i) {
      z[i] = centered(mod_q(std::int64_t(y[i]) + gc[i]));
      p_plus_dc[i] = mod_q(std::int64_t(p[i]) + dc[i]);
    }
    if (!poly_norm_below(z, Z_BOUND)) continue;
    bool low_ok = true;
    for (int x : p_plus_dc) {
      if (std::abs(low_bits(x)) >= LOW_BOUND) {
        low_ok = false;
        break;
      }
    }
    if (!low_ok) continue;
    return SignResult{Signature{r, std::move(z)}, k + 1};
  }
  fail("Algorithm 4 signing counter exhausted");
}

inline Bytes oracle_lambda(const Digest32 &oracle_seed,
                           std::uint32_t signature_index) {
  return shake256({bytes_of("EagleSignV3 public reproducer lambda"),
                   bytes_of(oracle_seed),
                   u32le(signature_index)},
                  48);
}

}  // namespace esv3

