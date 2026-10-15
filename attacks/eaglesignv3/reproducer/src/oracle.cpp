#include "secret_scheme.hpp"

using namespace esv3;

int main(int argc, char **argv) {
  try {
    if (argc != 6) {
      std::cerr << "usage: oracle SECRET_KEY PUBLIC_KEY TRANSCRIPTS COUNT SUMMARY\n";
      return 2;
    }
    const SecretKey sk = read_secret_key(argv[1]);
    const PublicKey pk = read_public_key(argv[2]);
    if (pk.rho != sk.pk.rho || pk.t != sk.pk.t) fail("public/secret key mismatch");
    const unsigned long parsed = std::stoul(argv[4]);
    if (parsed == 0 || parsed > 1000000) fail("invalid transcript count");
    const std::uint32_t count = static_cast<std::uint32_t>(parsed);

    const Poly t_hat = ntt().forward(pk.t);
    const Poly a = expand_a(pk.rho);
    const Digest32 tr = compute_tr(pk);
    std::vector<Transcript> records;
    records.reserve(count);
    std::uint64_t total_internal_attempts = 0;
    std::uint32_t accepted = 0, rejected = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
      const std::string m = oracle_message(i);
      const Bytes message(m.begin(), m.end());
      const Bytes lambda = oracle_lambda(sk.oracle_seed, i);
      SignResult signed_result =
          sign_with_lambda(pk, sk.d, sk.g, message, lambda, &t_hat);
      const bool ok = verify_signature_precomputed(pk, message,
                                                   signed_result.signature, tr,
                                                   a, t_hat);
      accepted += ok;
      rejected += !ok;
      total_internal_attempts += signed_result.internal_attempts;
      records.push_back(Transcript{message, std::move(signed_result.signature),
                                   ok, signed_result.internal_attempts});
      if ((i + 1) % 5000 == 0) {
        std::cerr << "oracle returned " << (i + 1) << "/" << count << "\n";
      }
    }
    write_transcripts(argv[3], records);
    std::ofstream report(argv[5]);
    if (!report) fail("cannot create oracle summary");
    report << "status=PASS\n"
           << "algorithm4_returned_signatures=" << count << "\n"
           << "ordinary_verifier_accepted=" << accepted << "\n"
           << "ordinary_verifier_rejected=" << rejected << "\n"
           << "verifier_filter_applied=false\n"
           << "total_internal_rejection_attempts=" << total_internal_attempts
           << "\n"
           << "average_internal_attempts=" << std::setprecision(12)
           << (double(total_internal_attempts) / count) << "\n";
    std::cout << "ORACLE: PASS returned=" << count << " accepted=" << accepted
              << " verifier_rejected_retained=" << rejected << "\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "ORACLE: FAIL: " << e.what() << "\n";
    return 1;
  }
}

