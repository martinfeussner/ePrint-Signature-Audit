#include "public_scheme.hpp"

#include <cmath>
#include <filesystem>
#include <map>

using namespace esv3;

namespace {

struct Edge {
  int coordinate;
  int a;
  bool lower;
};

struct Constraint {
  std::array<int, TAU> index{};
  std::array<int, TAU> coefficient{};
  int rhs = 0;
  std::uint32_t transcript = 0;
  int coordinate = 0;
  int a = 0;
  bool lower = false;
  bool flip = false;
};

struct Collection {
  std::vector<Constraint> constraints;
  std::uint32_t transcripts = 0;
  std::uint32_t verifier_accepted = 0;
  std::uint32_t verifier_rejected = 0;
  std::uint64_t total_candidates = 0;
  std::uint64_t flips = 0;
  std::array<std::uint64_t, BETA> threshold_count{};
  std::array<std::uint64_t, BETA> threshold_flips{};
  int max_edges = 0;
};

Bytes u32le_local(unsigned x) {
  return Bytes{static_cast<std::uint8_t>(x & 0xff),
               static_cast<std::uint8_t>((x >> 8) & 0xff),
               static_cast<std::uint8_t>((x >> 16) & 0xff),
               static_cast<std::uint8_t>((x >> 24) & 0xff)};
}

std::array<std::pair<int, int>, TAU> convolution_row(const Poly &c, int output) {
  std::array<std::pair<int, int>, TAU> row{};
  int used = 0;
  for (int b = 0; b < N; ++b) {
    if (c[b] == 0) continue;
    if (used >= TAU) fail("challenge weight exceeds tau");
    if (b <= output) {
      row[used++] = {output - b, c[b]};
    } else {
      row[used++] = {output - b + N, -c[b]};
    }
  }
  if (used != TAU) fail("challenge weight is not tau");
  return row;
}

Collection collect(const PublicKey &pk, const std::vector<Transcript> &records) {
  Collection out;
  out.transcripts = static_cast<std::uint32_t>(records.size());
  const Digest32 tr = compute_tr(pk);
  const Poly a_poly = expand_a(pk.rho);
  const Poly t_hat = ntt().forward(pk.t);
  for (std::uint32_t record_index = 0; record_index < records.size();
       ++record_index) {
    const Transcript &rec = records[record_index];
    const Bytes mu = compute_mu(tr, rec.message);
    const Poly c = challenge(mu, rec.signature.r);
    const Poly tz = poly_mul_pretransformed(t_hat, rec.signature.z);
    const Poly ac = sparse_mul(a_poly, c);
    Poly v(N), base_high(N);
    std::vector<Edge> edges;
    for (int i = 0; i < N; ++i) {
      v[i] = mod_q(std::int64_t(tz[i]) - ac[i]);
      base_high[i] = high_bits(v[i]);
      const int vc = centered(v[i]);
      if (vc >= -HALF_Q && vc <= -HALF_Q + (BETA - 1)) {
        edges.push_back(Edge{i, vc + HALF_Q, true});
      } else if (vc <= HALF_Q && vc >= HALF_Q - (BETA - 1)) {
        edges.push_back(Edge{i, HALF_Q - vc, false});
      }
    }
    out.max_edges = std::max(out.max_edges, static_cast<int>(edges.size()));
    if (edges.size() > 24) fail("unexpectedly many edge coordinates");
    const std::uint64_t candidate_count = std::uint64_t(1) << edges.size();
    out.total_candidates += candidate_count;
    std::uint64_t winning_mask = 0;
    int matches = 0;
    for (std::uint64_t mask = 0; mask < candidate_count; ++mask) {
      Poly candidate(base_high);
      for (std::size_t j = 0; j < edges.size(); ++j) {
        if ((mask >> j) & 1) {
          candidate[edges[j].coordinate] = edges[j].lower ? 1 : -1;
        }
      }
      if (digest_equal(hash_highbits(candidate), rec.signature.r)) {
        ++matches;
        winning_mask = mask;
      }
    }
    if (matches != 1) {
      std::ostringstream msg;
      msg << "transcript " << record_index << " has " << matches
          << " matching edge candidates";
      fail(msg.str());
    }
    const Digest64 r_prime = hash_highbits(base_high);
    const bool verifier_ok = challenge(mu, rec.signature.r) == challenge(mu, r_prime) &&
                             poly_norm_below(rec.signature.z, Z_BOUND);
    if (verifier_ok != rec.verifier_accepted) {
      fail("stored oracle verifier flag disagrees with public recomputation");
    }
    out.verifier_accepted += verifier_ok;
    out.verifier_rejected += !verifier_ok;

    for (std::size_t j = 0; j < edges.size(); ++j) {
      const Edge &edge = edges[j];
      const bool flip = ((winning_mask >> j) & 1) != 0;
      auto row = convolution_row(c, edge.coordinate);
      Constraint con;
      con.transcript = record_index;
      con.coordinate = edge.coordinate;
      con.a = edge.a;
      con.lower = edge.lower;
      con.flip = flip;
      int multiplier = 1;
      if (edge.lower) {
        if (flip) {
          multiplier = -1;       // s >= a+1  -> -s <= -(a+1)
          con.rhs = -(edge.a + 1);
        } else {
          con.rhs = edge.a;      // s <= a
        }
      } else {
        if (flip) {
          con.rhs = -(edge.a + 1);  // s <= -a-1
        } else {
          multiplier = -1;          // s >= -a -> -s <= a
          con.rhs = edge.a;
        }
      }
      for (int k = 0; k < TAU; ++k) {
        con.index[k] = row[k].first;
        con.coefficient[k] = multiplier * row[k].second;
      }
      out.constraints.push_back(con);
      ++out.threshold_count[edge.a];
      if (flip) {
        ++out.flips;
        ++out.threshold_flips[edge.a];
      }
    }
    if ((record_index + 1) % 5000 == 0) {
      std::cerr << "attacker processed " << (record_index + 1) << "/"
                << records.size() << " transcripts\n";
    }
  }
  return out;
}

void write_lp(const std::string &path, const Collection &data) {
  std::ofstream out(path);
  if (!out) fail("cannot create LP file");
  out << "Minimize\n obj: 0 x0\nSubject To\n";
  for (std::size_t j = 0; j < data.constraints.size(); ++j) {
    const Constraint &c = data.constraints[j];
    out << " c" << j << ":";
    for (int k = 0; k < TAU; ++k) {
      const int coef = c.coefficient[k];
      out << (coef >= 0 ? " + " : " - ") << std::abs(coef) << " x"
          << c.index[k];
    }
    out << " <= " << c.rhs << "\n";
  }
  out << "Bounds\n";
  for (int i = 0; i < N; ++i) out << " -1 <= x" << i << " <= 1\n";
  out << "Generals\n";
  for (int i = 0; i < N; ++i) {
    out << " x" << i;
    if ((i + 1) % 16 == 0) out << '\n';
  }
  if (N % 16) out << '\n';
  out << "End\n";
  if (!out) fail("failed writing LP file");
}

void write_collection_report(const std::string &path, const Collection &data) {
  std::ofstream out(path);
  if (!out) fail("cannot create constraint report");
  out << "status=PASS\n"
      << "transcripts=" << data.transcripts << "\n"
      << "ordinary_verifier_accepted=" << data.verifier_accepted << "\n"
      << "ordinary_verifier_rejected=" << data.verifier_rejected << "\n"
      << "edge_constraints=" << data.constraints.size() << "\n"
      << "edge_flips=" << data.flips << "\n"
      << "max_edges_in_one_transcript=" << data.max_edges << "\n"
      << "hash_candidates_tested=" << data.total_candidates << "\n"
      << "unique_hash_match_for_every_transcript=true\n";
  for (int a = 0; a < BETA; ++a) {
    out << "threshold_" << a << "_constraints=" << data.threshold_count[a]
        << "\n"
        << "threshold_" << a << "_flips=" << data.threshold_flips[a] << "\n";
  }
}

Poly read_solver_solution(const std::string &path) {
  std::ifstream in(path);
  if (!in) fail("cannot open solver solution");
  // The solution format may omit variables whose value is zero.
  Poly d(N, 0);
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream row(line);
    std::string first, name, value_text;
    if (!(row >> first >> name >> value_text)) continue;
    if (name.size() < 2 || name[0] != 'x') continue;
    char *end = nullptr;
    const long index = std::strtol(name.c_str() + 1, &end, 10);
    if (!end || *end != '\0' || index < 0 || index >= N) continue;
    const double value = std::stod(value_text);
    const long rounded = std::lround(value);
    if (std::abs(value - rounded) > 1e-7 || rounded < -1 || rounded > 1) {
      fail("solver returned nonternary value");
    }
    d[static_cast<std::size_t>(index)] = static_cast<int>(rounded);
  }
  return d;
}

void validate_constraints(const Collection &data, const Poly &d) {
  for (std::size_t j = 0; j < data.constraints.size(); ++j) {
    const Constraint &c = data.constraints[j];
    int lhs = 0;
    for (int k = 0; k < TAU; ++k) lhs += c.coefficient[k] * d[c.index[k]];
    if (lhs > c.rhs) {
      fail("recovered D violates constraint " + std::to_string(j));
    }
  }
}

Poly sample_attacker_y(const Bytes &lambda, unsigned k) {
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

std::pair<Signature, std::uint32_t> attacker_sign_once(
    const PublicKey &pk, const Poly &d, const Poly &g, const Bytes &message,
    const Bytes &lambda, const Poly &t_hat) {
  const Digest32 tr = compute_tr(pk);
  const Bytes mu = compute_mu(tr, message);
  for (unsigned k = 0; k <= 65535; ++k) {
    const Poly y = sample_attacker_y(lambda, k);
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
    return {Signature{r, std::move(z)}, k + 1};
  }
  fail("attacker signing counter exhausted");
}

Bytes attacker_lambda(const PublicKey &pk, std::uint32_t outer) {
  return shake256({bytes_of("EagleSignV3 public reproducer recovered signer lambda"),
                   bytes_of(pk.rho), encode_poly_u16(pk.t),
                   u32le_local(outer)},
                  48);
}

int prepare(int argc, char **argv) {
  if (argc != 6) {
    std::cerr << "usage: recover prepare PK TRANSCRIPTS LP REPORT\n";
    return 2;
  }
  const PublicKey pk = read_public_key(argv[2]);
  if (!poly_is_unit(pk.t)) fail("selected public T is not a unit");
  const auto records = read_transcripts(argv[3]);
  const Collection data = collect(pk, records);
  write_lp(argv[4], data);
  write_collection_report(argv[5], data);
  std::cout << "RECOVER PREPARE: PASS constraints=" << data.constraints.size()
            << " flips=" << data.flips << "\n";
  return 0;
}

int finalize(int argc, char **argv) {
  if (argc != 8) {
    std::cerr << "usage: recover finalize PK TRANSCRIPTS SOLVER_SOLUTION RECOVERED_KEY FORGERY REPORT\n";
    return 2;
  }
  const PublicKey pk = read_public_key(argv[2]);
  if (!poly_is_unit(pk.t)) fail("selected public T is not a unit");
  const auto records = read_transcripts(argv[3]);
  const Collection data = collect(pk, records);
  const Poly d = read_solver_solution(argv[4]);
  validate_constraints(data, d);

  const Poly a = expand_a(pk.rho);
  Poly a_plus_d(N);
  for (int i = 0; i < N; ++i) a_plus_d[i] = mod_q(a[i] + d[i]);
  Poly g_residue = poly_mul(poly_inverse(pk.t), a_plus_d);
  Poly g(N);
  for (int i = 0; i < N; ++i) {
    g[i] = centered(g_residue[i]);
    if (g[i] < -1 || g[i] > 1) {
      fail("constraint solution does not derive a ternary G; transcript set underdetermined");
    }
  }
  if (!poly_is_unit(g)) fail("derived G is not a unit");
  if (!public_relation_holds(pk, d, g)) fail("public identity T*G=A+D failed");

  const Bytes message = fresh_message();
  for (const Transcript &rec : records) {
    if (rec.message == message) fail("fresh message appears in oracle transcript");
  }
  const Poly t_hat = ntt().forward(pk.t);
  Signature forgery;
  std::uint32_t selected_outer = 0, selected_internal = 0;
  bool forged = false;
  for (std::uint32_t outer = 0; outer < 1000; ++outer) {
    auto result = attacker_sign_once(pk, d, g, message,
                                     attacker_lambda(pk, outer), t_hat);
    if (verify_signature(pk, message, result.first)) {
      forgery = std::move(result.first);
      selected_outer = outer;
      selected_internal = result.second;
      forged = true;
      break;
    }
  }
  if (!forged) fail("recovered signer did not obtain an accepted fresh signature");

  write_recovered_key(argv[5], RecoveredKey{d, g});
  write_signature_artifact(argv[6], message, forgery);
  std::ofstream report(argv[7]);
  if (!report) fail("cannot create recovery report");
  int d_neg = 0, d_zero = 0, d_pos = 0;
  int g_neg = 0, g_zero = 0, g_pos = 0;
  for (int x : d) (x < 0 ? d_neg : (x > 0 ? d_pos : d_zero))++;
  for (int x : g) (x < 0 ? g_neg : (x > 0 ? g_pos : g_zero))++;
  report << "status=PASS\n"
         << "inputs=public_key,ordinary_transcripts,solver_solution_only\n"
         << "hidden_key_access=false\n"
         << "constraints=" << data.constraints.size() << "\n"
         << "all_constraints_satisfied=true\n"
         << "recovered_D_ternary=true\n"
         << "derived_G_ternary=true\n"
         << "derived_G_unit=true\n"
         << "public_TG_equals_A_plus_D=true\n"
         << "D_counts_minus_zero_plus=" << d_neg << ',' << d_zero << ',' << d_pos
         << "\n"
         << "G_counts_minus_zero_plus=" << g_neg << ',' << g_zero << ',' << g_pos
         << "\n"
         << "fresh_message_hex=" << hex(message) << "\n"
         << "fresh_message_absent_from_queries=true\n"
         << "accepted_forgery_outer_attempt=" << selected_outer << "\n"
         << "accepted_forgery_internal_attempts=" << selected_internal << "\n";
  std::cout << "RECOVER FINALIZE: PASS public_relation=true fresh_forgery=true\n";
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  try {
    if (argc < 2) return 2;
    const std::string mode = argv[1];
    if (mode == "prepare") return prepare(argc, argv);
    if (mode == "finalize") return finalize(argc, argv);
    std::cerr << "unknown recover mode\n";
    return 2;
  } catch (const std::exception &e) {
    std::cerr << "RECOVER: FAIL: " << e.what() << "\n";
    return 1;
  }
}

