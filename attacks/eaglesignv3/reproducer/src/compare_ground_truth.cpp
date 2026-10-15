#include "secret_scheme.hpp"

using namespace esv3;

int main(int argc, char **argv) {
  try {
    if (argc != 4) {
      std::cerr << "usage: compare_ground_truth SECRET_KEY RECOVERED_KEY REPORT\n";
      return 2;
    }
    const SecretKey truth = read_secret_key(argv[1]);
    const RecoveredKey recovered = read_recovered_key(argv[2]);
    const bool d_exact = truth.d == recovered.d;
    const bool g_exact = truth.g == recovered.g;
    const bool equivalent = public_relation_holds(truth.pk, recovered.d, recovered.g);
    if (!equivalent) fail("recovered pair is not a public equivalent signing key");
    std::ofstream report(argv[3]);
    if (!report) fail("cannot create ground-truth report");
    report << "status=PASS\n"
           << "stage=post-hoc after independent verification gate\n"
           << "D_exact_match=" << (d_exact ? "true" : "false") << "\n"
           << "G_exact_match=" << (g_exact ? "true" : "false") << "\n"
           << "public_equivalent_pair=" << (equivalent ? "true" : "false") << "\n";
    std::cout << "GROUND TRUTH: PASS D_exact=" << (d_exact ? "true" : "false")
              << " G_exact=" << (g_exact ? "true" : "false") << "\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "GROUND TRUTH: FAIL: " << e.what() << "\n";
    return 1;
  }
}

