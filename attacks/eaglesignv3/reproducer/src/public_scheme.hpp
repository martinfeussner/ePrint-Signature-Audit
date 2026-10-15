#pragma once

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace esv3 {

constexpr int N = 1024;
constexpr int Q = 59393;
constexpr int HALF_Q = 29696;
constexpr int TAU = 16;
constexpr int ETA = 1;
constexpr int BETA = 16;
constexpr int GAMMA1 = 16384;
constexpr int GAMMA2 = 16384;
constexpr int ALPHA = 2 * GAMMA2;
constexpr int Z_BOUND = GAMMA1 - BETA;
constexpr int LOW_BOUND = GAMMA2 - BETA;

using Bytes = std::vector<std::uint8_t>;
using Poly = std::vector<int>;
using Digest32 = std::array<std::uint8_t, 32>;
using Digest64 = std::array<std::uint8_t, 64>;

[[noreturn]] inline void fail(const std::string &s) {
  throw std::runtime_error(s);
}

inline int mod_q(std::int64_t x) {
  x %= Q;
  if (x < 0) x += Q;
  return static_cast<int>(x);
}

inline int centered(int x) {
  x = mod_q(x);
  return x > HALF_Q ? x - Q : x;
}

inline int centered_even(std::int64_t x, int modulus) {
  std::int64_t r = x % modulus;
  if (r <= -(modulus / 2)) r += modulus;
  if (r > modulus / 2) r -= modulus;
  return static_cast<int>(r);
}

inline int low_bits(int residue) {
  return centered_even(centered(residue), ALPHA);
}

inline int high_bits(int residue) {
  const int x = centered(residue);
  const int lo = centered_even(x, ALPHA);
  return (x - lo) / ALPHA;
}

inline int pow_mod(int base, std::int64_t exp) {
  std::int64_t x = mod_q(base), out = 1;
  while (exp > 0) {
    if (exp & 1) out = (out * x) % Q;
    x = (x * x) % Q;
    exp >>= 1;
  }
  return static_cast<int>(out);
}

inline int inv_mod(int x) {
  if (mod_q(x) == 0) fail("inverse of zero");
  return pow_mod(x, Q - 2);
}

inline int primitive_generator() {
  for (int g = 2; g < Q; ++g) {
    if (pow_mod(g, (Q - 1) / 2) != 1 &&
        pow_mod(g, (Q - 1) / 29) != 1) {
      return g;
    }
  }
  fail("no primitive generator");
}

struct NegacyclicNTT {
  int psi;
  int psi_inv;
  int omega;
  int omega_inv;
  int n_inv;
  Poly twist;
  Poly untwist;

  NegacyclicNTT()
      : psi(pow_mod(primitive_generator(), (Q - 1) / (2 * N))),
        psi_inv(inv_mod(psi)), omega(mod_q(std::int64_t(psi) * psi)),
        omega_inv(inv_mod(omega)), n_inv(inv_mod(N)), twist(N),
        untwist(N) {
    twist[0] = 1;
    untwist[0] = 1;
    for (int i = 1; i < N; ++i) {
      twist[i] = mod_q(std::int64_t(twist[i - 1]) * psi);
      untwist[i] = mod_q(std::int64_t(untwist[i - 1]) * psi_inv);
    }
    if (pow_mod(psi, N) != Q - 1 || pow_mod(psi, 2 * N) != 1) {
      fail("invalid negacyclic root");
    }
  }

  static void cyclic_ntt(Poly &a, int root) {
    if (static_cast<int>(a.size()) != N) fail("bad NTT length");
    for (int i = 1, j = 0; i < N; ++i) {
      int bit = N >> 1;
      for (; j & bit; bit >>= 1) j ^= bit;
      j ^= bit;
      if (i < j) std::swap(a[i], a[j]);
    }
    for (int len = 2; len <= N; len <<= 1) {
      const int wlen = pow_mod(root, N / len);
      for (int i = 0; i < N; i += len) {
        int w = 1;
        for (int j = 0; j < len / 2; ++j) {
          const int u = a[i + j];
          const int v = mod_q(std::int64_t(a[i + j + len / 2]) * w);
          a[i + j] = mod_q(u + v);
          a[i + j + len / 2] = mod_q(u - v);
          w = mod_q(std::int64_t(w) * wlen);
        }
      }
    }
  }

  Poly forward(const Poly &a) const {
    if (static_cast<int>(a.size()) != N) fail("bad polynomial length");
    Poly out(N);
    for (int i = 0; i < N; ++i) {
      out[i] = mod_q(std::int64_t(mod_q(a[i])) * twist[i]);
    }
    cyclic_ntt(out, omega);
    return out;
  }

  Poly inverse(const Poly &a_hat) const {
    if (static_cast<int>(a_hat.size()) != N) fail("bad transform length");
    Poly out = a_hat;
    cyclic_ntt(out, omega_inv);
    for (int i = 0; i < N; ++i) {
      out[i] = mod_q(std::int64_t(out[i]) * n_inv);
      out[i] = mod_q(std::int64_t(out[i]) * untwist[i]);
    }
    return out;
  }
};

inline const NegacyclicNTT &ntt() {
  static const NegacyclicNTT ctx;
  return ctx;
}

inline Poly pointwise_product(const Poly &a_hat, const Poly &b_hat) {
  Poly out(N);
  for (int i = 0; i < N; ++i) {
    out[i] = mod_q(std::int64_t(a_hat[i]) * b_hat[i]);
  }
  return out;
}

inline Poly poly_mul(const Poly &a, const Poly &b) {
  return ntt().inverse(pointwise_product(ntt().forward(a), ntt().forward(b)));
}

inline Poly poly_mul_pretransformed(const Poly &a_hat, const Poly &b) {
  return ntt().inverse(pointwise_product(a_hat, ntt().forward(b)));
}

inline bool poly_is_unit(const Poly &a) {
  const Poly ah = ntt().forward(a);
  return std::all_of(ah.begin(), ah.end(), [](int x) { return x != 0; });
}

inline Poly poly_inverse(const Poly &a) {
  Poly ah = ntt().forward(a);
  for (int &x : ah) {
    if (x == 0) fail("polynomial is not a unit");
    x = inv_mod(x);
  }
  return ntt().inverse(ah);
}

inline Poly sparse_mul(const Poly &a, const Poly &sparse) {
  if (static_cast<int>(a.size()) != N || static_cast<int>(sparse.size()) != N) {
    fail("bad sparse multiplication length");
  }
  std::vector<std::pair<int, int>> support;
  for (int j = 0; j < N; ++j) {
    if (sparse[j] != 0) support.emplace_back(j, sparse[j]);
  }
  Poly out(N, 0);
  for (const auto &[j, sign] : support) {
    for (int i = 0; i < N; ++i) {
      const int idx = i + j;
      if (idx < N) {
        out[idx] += sign * a[i];
      } else {
        out[idx - N] -= sign * a[i];
      }
    }
  }
  return out;
}

inline Bytes shake(const EVP_MD *md, const std::vector<Bytes> &parts,
                   std::size_t out_len) {
  EVP_MD_CTX *raw = EVP_MD_CTX_new();
  if (!raw) fail("EVP_MD_CTX_new failed");
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(raw,
                                                              EVP_MD_CTX_free);
  if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) fail("DigestInit failed");
  for (const auto &part : parts) {
    if (!part.empty() &&
        EVP_DigestUpdate(ctx.get(), part.data(), part.size()) != 1) {
      fail("DigestUpdate failed");
    }
  }
  Bytes out(out_len);
  if (EVP_DigestFinalXOF(ctx.get(), out.data(), out.size()) != 1) {
    fail("DigestFinalXOF failed");
  }
  return out;
}

inline Bytes shake128(const std::vector<Bytes> &parts, std::size_t out_len) {
  return shake(EVP_shake128(), parts, out_len);
}

inline Bytes shake256(const std::vector<Bytes> &parts, std::size_t out_len) {
  return shake(EVP_shake256(), parts, out_len);
}

inline Bytes bytes_of(std::string_view s) {
  return Bytes(s.begin(), s.end());
}

inline Bytes bytes_of(const Digest32 &d) { return Bytes(d.begin(), d.end()); }
inline Bytes bytes_of(const Digest64 &d) { return Bytes(d.begin(), d.end()); }

inline Digest32 digest32(const Bytes &b) {
  if (b.size() != 32) fail("digest length is not 32");
  Digest32 d{};
  std::copy(b.begin(), b.end(), d.begin());
  return d;
}

inline Digest64 digest64(const Bytes &b) {
  if (b.size() != 64) fail("digest length is not 64");
  Digest64 d{};
  std::copy(b.begin(), b.end(), d.begin());
  return d;
}

inline std::string hex(const Bytes &b) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (auto x : b) out << std::setw(2) << static_cast<unsigned>(x);
  return out.str();
}

inline Bytes u16le(unsigned x) {
  return Bytes{static_cast<std::uint8_t>(x & 0xff),
               static_cast<std::uint8_t>((x >> 8) & 0xff)};
}

inline Bytes encode_poly_u16(const Poly &p) {
  if (static_cast<int>(p.size()) != N) fail("bad polynomial encoding length");
  Bytes out;
  out.reserve(2 * N);
  for (int x : p) {
    const unsigned r = static_cast<unsigned>(mod_q(x));
    out.push_back(static_cast<std::uint8_t>(r & 0xff));
    out.push_back(static_cast<std::uint8_t>((r >> 8) & 0xff));
  }
  return out;
}

inline Bytes encode_highbits(const Poly &h) {
  if (static_cast<int>(h.size()) != N) fail("bad high-bits length");
  Bytes out(N);
  for (int i = 0; i < N; ++i) {
    if (h[i] < -1 || h[i] > 1) fail("high bit outside {-1,0,1}");
    out[i] = static_cast<std::uint8_t>(h[i] + 1);
  }
  return out;
}

inline Poly high_bits_poly(const Poly &p) {
  Poly out(N);
  for (int i = 0; i < N; ++i) out[i] = high_bits(p[i]);
  return out;
}

inline Digest64 hash_highbits(const Poly &h) {
  return digest64(shake256({encode_highbits(h)}, 64));
}

inline Poly expand_a(const Digest32 &rho) {
  Bytes stream = shake128({bytes_of(rho), u16le(0)}, 8192);
  Poly out;
  out.reserve(N);
  for (std::size_t pos = 0; pos + 1 < stream.size() && out.size() < N;
       pos += 2) {
    const unsigned x = unsigned(stream[pos]) | (unsigned(stream[pos + 1]) << 8);
    if (x < Q) out.push_back(static_cast<int>(x));
  }
  if (static_cast<int>(out.size()) != N) fail("A sampler exhausted stream");
  return out;
}

struct PublicKey {
  Digest32 rho{};
  Poly t;
};

struct Signature {
  Digest64 r{};
  Poly z;
};

struct Transcript {
  Bytes message;
  Signature signature;
  bool verifier_accepted = false;
  std::uint32_t internal_attempts = 0;
};

struct RecoveredKey {
  Poly d;
  Poly g;
};

inline Digest32 compute_tr(const PublicKey &pk) {
  return digest32(shake256({bytes_of(pk.rho), encode_poly_u16(pk.t)}, 32));
}

inline Bytes compute_mu(const Digest32 &tr, const Bytes &message) {
  return shake256({bytes_of(tr), message}, 48);
}

struct ByteStream {
  Bytes data;
  std::size_t pos = 0;

  explicit ByteStream(Bytes d) : data(std::move(d)) {}

  std::uint8_t byte() {
    if (pos >= data.size()) fail("XOF stream exhausted");
    return data[pos++];
  }

  unsigned u16() {
    const unsigned lo = byte();
    return lo | (unsigned(byte()) << 8);
  }

  unsigned uniform(unsigned bound) {
    if (bound == 0 || bound > 65536) fail("invalid uniform bound");
    const unsigned lim = 65536u - (65536u % bound);
    for (;;) {
      const unsigned x = u16();
      if (x < lim) return x % bound;
    }
  }
};

inline Poly challenge(const Bytes &mu, const Digest64 &r) {
  const Bytes seedc = shake256({mu, bytes_of(r)}, 80);
  ByteStream xof(shake128({seedc, u16le(0)}, 8192));
  Poly d(N, 0);
  for (int i = N - TAU; i < N; ++i) {
    const int b = static_cast<int>(xof.uniform(static_cast<unsigned>(i + 1)));
    d[i] = d[b];
    const int sign = (xof.byte() & 1) ? -1 : 1;
    d[b] = sign;
  }
  int weight = 0;
  for (int x : d) weight += (x != 0);
  if (weight != TAU) fail("challenge sampler weight failure");
  return d;
}

template <std::size_t L>
inline bool digest_equal(const std::array<std::uint8_t, L> &a,
                         const std::array<std::uint8_t, L> &b) {
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

inline bool poly_norm_below(const Poly &p, int bound) {
  for (int x : p) {
    if (std::abs(centered(x)) >= bound) return false;
  }
  return true;
}

inline bool verify_signature_precomputed(const PublicKey &pk, const Bytes &message,
                                         const Signature &sig,
                                         const Digest32 &tr, const Poly &a,
                                         const Poly &t_hat) {
  if (static_cast<int>(pk.t.size()) != N || static_cast<int>(sig.z.size()) != N) {
    return false;
  }
  if (!poly_norm_below(sig.z, Z_BOUND)) return false;
  const Bytes mu = compute_mu(tr, message);
  const Poly c_prime = challenge(mu, sig.r);
  const Poly tz = poly_mul_pretransformed(t_hat, sig.z);
  const Poly ac = sparse_mul(a, c_prime);
  Poly v(N);
  for (int i = 0; i < N; ++i) v[i] = mod_q(std::int64_t(tz[i]) - ac[i]);
  const Digest64 r_prime = hash_highbits(high_bits_poly(v));
  const Poly c_check = challenge(mu, r_prime);
  return c_prime == c_check;
}

inline bool verify_signature(const PublicKey &pk, const Bytes &message,
                             const Signature &sig) {
  const Digest32 tr = compute_tr(pk);
  const Poly a = expand_a(pk.rho);
  const Poly t_hat = ntt().forward(pk.t);
  return verify_signature_precomputed(pk, message, sig, tr, a, t_hat);
}

inline bool public_relation_holds(const PublicKey &pk, const Poly &d,
                                  const Poly &g) {
  if (static_cast<int>(d.size()) != N || static_cast<int>(g.size()) != N) {
    return false;
  }
  const Poly a = expand_a(pk.rho);
  const Poly tg = poly_mul(pk.t, g);
  for (int i = 0; i < N; ++i) {
    if (mod_q(tg[i]) != mod_q(a[i] + d[i])) return false;
  }
  return true;
}

inline void write_u16(std::ostream &out, std::uint16_t x) {
  const char b[2] = {static_cast<char>(x & 0xff),
                     static_cast<char>((x >> 8) & 0xff)};
  out.write(b, 2);
}

inline void write_u32(std::ostream &out, std::uint32_t x) {
  for (int i = 0; i < 4; ++i) out.put(static_cast<char>((x >> (8 * i)) & 0xff));
}

inline std::uint16_t read_u16(std::istream &in) {
  std::uint16_t x = 0;
  for (int i = 0; i < 2; ++i) {
    const int c = in.get();
    if (c == EOF) fail("unexpected EOF reading u16");
    x |= static_cast<std::uint16_t>(static_cast<unsigned char>(c)) << (8 * i);
  }
  return x;
}

inline std::uint32_t read_u32(std::istream &in) {
  std::uint32_t x = 0;
  for (int i = 0; i < 4; ++i) {
    const int c = in.get();
    if (c == EOF) fail("unexpected EOF reading u32");
    x |= static_cast<std::uint32_t>(static_cast<unsigned char>(c)) << (8 * i);
  }
  return x;
}

inline void write_magic(std::ostream &out, const std::array<char, 8> &magic) {
  out.write(magic.data(), magic.size());
}

inline void expect_magic(std::istream &in, const std::array<char, 8> &magic) {
  std::array<char, 8> got{};
  in.read(got.data(), got.size());
  if (!in || got != magic) fail("file magic mismatch");
}

inline void write_bytes(std::ostream &out, const Bytes &b) {
  out.write(reinterpret_cast<const char *>(b.data()), b.size());
}

inline Bytes read_bytes(std::istream &in, std::size_t n) {
  Bytes b(n);
  in.read(reinterpret_cast<char *>(b.data()), b.size());
  if (!in) fail("unexpected EOF reading bytes");
  return b;
}

template <std::size_t L>
inline void write_digest(std::ostream &out,
                         const std::array<std::uint8_t, L> &d) {
  out.write(reinterpret_cast<const char *>(d.data()), d.size());
}

inline Digest32 read_digest32(std::istream &in) {
  Digest32 d{};
  in.read(reinterpret_cast<char *>(d.data()), d.size());
  if (!in) fail("unexpected EOF reading digest");
  return d;
}

inline Digest64 read_digest64(std::istream &in) {
  Digest64 d{};
  in.read(reinterpret_cast<char *>(d.data()), d.size());
  if (!in) fail("unexpected EOF reading 64-byte digest");
  return d;
}

inline void write_public_key(const std::string &path, const PublicKey &pk) {
  std::ofstream out(path, std::ios::binary);
  if (!out) fail("cannot create public key: " + path);
  write_magic(out, {'E', 'S', 'V', '3', 'P', 'K', '1', '\0'});
  write_digest(out, pk.rho);
  for (int x : pk.t) write_u16(out, static_cast<std::uint16_t>(mod_q(x)));
  if (!out) fail("failed writing public key");
}

inline PublicKey read_public_key(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail("cannot open public key: " + path);
  expect_magic(in, {'E', 'S', 'V', '3', 'P', 'K', '1', '\0'});
  PublicKey pk;
  pk.rho = read_digest32(in);
  pk.t.resize(N);
  for (int &x : pk.t) {
    x = read_u16(in);
    if (x >= Q) fail("noncanonical public-key coefficient");
  }
  if (in.peek() != EOF) fail("trailing public-key data");
  return pk;
}

inline void write_transcripts(const std::string &path,
                              const std::vector<Transcript> &records) {
  std::ofstream out(path, std::ios::binary);
  if (!out) fail("cannot create transcripts: " + path);
  write_magic(out, {'E', 'S', 'V', '3', 'T', 'R', '1', '\0'});
  write_u32(out, static_cast<std::uint32_t>(records.size()));
  for (const Transcript &rec : records) {
    write_u32(out, static_cast<std::uint32_t>(rec.message.size()));
    write_bytes(out, rec.message);
    write_digest(out, rec.signature.r);
    if (static_cast<int>(rec.signature.z.size()) != N) fail("bad z length");
    for (int z : rec.signature.z) {
      const int c = centered(z);
      if (c < std::numeric_limits<std::int16_t>::min() ||
          c > std::numeric_limits<std::int16_t>::max()) {
        fail("z coefficient does not fit int16");
      }
      write_u16(out, static_cast<std::uint16_t>(static_cast<std::int16_t>(c)));
    }
    out.put(rec.verifier_accepted ? 1 : 0);
    write_u32(out, rec.internal_attempts);
  }
  if (!out) fail("failed writing transcripts");
}

inline std::vector<Transcript> read_transcripts(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail("cannot open transcripts: " + path);
  expect_magic(in, {'E', 'S', 'V', '3', 'T', 'R', '1', '\0'});
  const std::uint32_t count = read_u32(in);
  std::vector<Transcript> records;
  records.reserve(count);
  for (std::uint32_t k = 0; k < count; ++k) {
    Transcript rec;
    const std::uint32_t mlen = read_u32(in);
    if (mlen > (1u << 20)) fail("unreasonable message length");
    rec.message = read_bytes(in, mlen);
    rec.signature.r = read_digest64(in);
    rec.signature.z.resize(N);
    for (int &z : rec.signature.z) {
      z = static_cast<std::int16_t>(read_u16(in));
    }
    const int accepted = in.get();
    if (accepted != 0 && accepted != 1) fail("bad verifier flag");
    rec.verifier_accepted = accepted == 1;
    rec.internal_attempts = read_u32(in);
    records.push_back(std::move(rec));
  }
  if (in.peek() != EOF) fail("trailing transcript data");
  return records;
}

inline void write_signature_artifact(const std::string &path,
                                     const Bytes &message,
                                     const Signature &sig) {
  std::ofstream out(path, std::ios::binary);
  if (!out) fail("cannot create signature artifact");
  write_magic(out, {'E', 'S', 'V', '3', 'S', 'G', '1', '\0'});
  write_u32(out, static_cast<std::uint32_t>(message.size()));
  write_bytes(out, message);
  write_digest(out, sig.r);
  for (int z : sig.z) {
    write_u16(out, static_cast<std::uint16_t>(static_cast<std::int16_t>(centered(z))));
  }
  if (!out) fail("failed writing signature artifact");
}

inline std::pair<Bytes, Signature> read_signature_artifact(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail("cannot open signature artifact");
  expect_magic(in, {'E', 'S', 'V', '3', 'S', 'G', '1', '\0'});
  const std::uint32_t mlen = read_u32(in);
  if (mlen > (1u << 20)) fail("unreasonable forged message length");
  Bytes message = read_bytes(in, mlen);
  Signature sig;
  sig.r = read_digest64(in);
  sig.z.resize(N);
  for (int &z : sig.z) z = static_cast<std::int16_t>(read_u16(in));
  if (in.peek() != EOF) fail("trailing signature artifact data");
  return {std::move(message), std::move(sig)};
}

inline void write_recovered_key(const std::string &path,
                                const RecoveredKey &key) {
  if (static_cast<int>(key.d.size()) != N ||
      static_cast<int>(key.g.size()) != N) {
    fail("bad recovered-key dimensions");
  }
  std::ofstream out(path, std::ios::binary);
  if (!out) fail("cannot create recovered key");
  write_magic(out, {'E', 'S', 'V', '3', 'R', 'K', '1', '\0'});
  for (const Poly *p : {&key.d, &key.g}) {
    for (int x : *p) {
      if (x < -1 || x > 1) fail("nonternary recovered key");
      out.put(static_cast<char>(static_cast<std::int8_t>(x)));
    }
  }
  if (!out) fail("failed writing recovered key");
}

inline RecoveredKey read_recovered_key(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail("cannot open recovered key");
  expect_magic(in, {'E', 'S', 'V', '3', 'R', 'K', '1', '\0'});
  RecoveredKey key{Poly(N), Poly(N)};
  for (Poly *p : {&key.d, &key.g}) {
    for (int &x : *p) {
      const int c = in.get();
      if (c == EOF) fail("EOF reading recovered key");
      x = static_cast<std::int8_t>(static_cast<unsigned char>(c));
      if (x < -1 || x > 1) fail("nonternary recovered-key encoding");
    }
  }
  if (in.peek() != EOF) fail("trailing recovered-key data");
  return key;
}

inline std::string oracle_message(std::uint32_t i) {
  std::ostringstream out;
  out << "EagleSignV3 public reproducer ordinary query "
      << std::setw(8) << std::setfill('0') << i;
  return out.str();
}

inline Bytes fresh_message() {
  return bytes_of("EagleSignV3 public reproducer fresh-message forgery");
}

}  // namespace esv3

