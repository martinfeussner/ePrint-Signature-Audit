#include "secret_scheme.hpp"

#include <filesystem>

using namespace esv3;

int main(int argc, char **argv) {
  try {
    if (argc != 3) {
      std::cerr << "usage: keygen TARGET_SEED RUN_DIRECTORY\n";
      return 2;
    }
    const std::string seed_path = argv[1];
    const std::filesystem::path run_dir = argv[2];
    std::ifstream seed_in(seed_path, std::ios::binary);
    if (!seed_in) fail("cannot open target seed");
    const Bytes target_seed = read_bytes(seed_in, 32);
    if (seed_in.peek() != EOF) fail("target seed must be exactly 32 bytes");

    std::filesystem::create_directories(run_dir / "private/key-attempts");
    std::filesystem::create_directories(run_dir / "public/key-attempts");
    std::ofstream ledger(run_dir / "public/key-attempts.tsv");
    if (!ledger) fail("cannot create key-attempt ledger");
    ledger << "attempt\tg_rehashes\tg_unit\tt_unit\tselected\tpublic_file\tprivate_file\n";

    bool selected = false;
    std::uint32_t selected_attempt = 0;
    for (std::uint32_t attempt = 0; attempt < 100; ++attempt) {
      const SecretKey sk = generate_key_attempt(target_seed, attempt);
      const bool g_unit = poly_is_unit(sk.g);
      const bool t_unit = poly_is_unit(sk.pk.t);
      std::ostringstream name;
      name << "attempt-" << std::setw(4) << std::setfill('0') << attempt;
      const std::string stem = name.str();
      const auto pub_path = run_dir / "public/key-attempts" / (stem + ".public.bin");
      const auto sec_path = run_dir / "private/key-attempts" / (stem + ".secret.bin");
      write_public_key(pub_path.string(), sk.pk);
      write_secret_key(sec_path.string(), sk);
      const bool choose = t_unit && !selected;
      ledger << attempt << '\t' << sk.g_rehashes << '\t' << (g_unit ? 1 : 0)
             << '\t' << (t_unit ? 1 : 0) << '\t' << (choose ? 1 : 0) << '\t'
             << pub_path.string() << '\t' << sec_path.string() << '\n';
      ledger.flush();
      if (choose) {
        write_public_key((run_dir / "public/public_key.bin").string(), sk.pk);
        write_secret_key((run_dir / "private/selected_secret_key.bin").string(), sk);
        selected = true;
        selected_attempt = attempt;
        break;
      }
    }
    if (!selected) fail("no unit-T key in 100 recorded attempts");
    std::ofstream summary(run_dir / "public/keygen-summary.txt");
    summary << "status=PASS\n"
            << "selected_attempt=" << selected_attempt << "\n"
            << "selection_rule=first unit-T key\n"
            << "all_generated_keys_recorded=true\n"
            << "claim_scope=one selected key\n";
    std::cout << "KEYGEN: PASS selected_attempt=" << selected_attempt << "\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "KEYGEN: FAIL: " << e.what() << "\n";
    return 1;
  }
}

