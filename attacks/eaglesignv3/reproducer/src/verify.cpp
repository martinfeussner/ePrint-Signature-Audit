#include "public_scheme.hpp"

using namespace esv3;

int main(int argc, char **argv) {
  try {
    if (argc != 6) {
      std::cerr << "usage: verify PK TRANSCRIPTS RECOVERED_KEY FORGERY REPORT\n";
      return 2;
    }
    const PublicKey pk = read_public_key(argv[1]);
    const auto records = read_transcripts(argv[2]);
    const RecoveredKey recovered = read_recovered_key(argv[3]);
    auto artifact = read_signature_artifact(argv[4]);
    const Bytes &message = artifact.first;
    const Signature &forgery = artifact.second;

    if (!public_relation_holds(pk, recovered.d, recovered.g)) {
      fail("public relation T*G=A+D rejected");
    }
    if (message != fresh_message()) fail("unexpected fresh-message value");
    for (const Transcript &rec : records) {
      if (rec.message == message) fail("forged message was previously queried");
    }
    const bool untouched_accept = verify_signature(pk, message, forgery);
    Bytes changed_message = message;
    changed_message.push_back(0x21);
    const bool changed_message_accept =
        verify_signature(pk, changed_message, forgery);
    Signature altered = forgery;
    altered.r[0] ^= 1;
    const bool altered_signature_accept = verify_signature(pk, message, altered);

    if (!untouched_accept) fail("ordinary verifier rejected untouched forgery");
    if (changed_message_accept) fail("changed-message control was accepted");
    if (altered_signature_accept) fail("altered-signature control was accepted");

    std::ofstream report(argv[5]);
    if (!report) fail("cannot create verification report");
    report << "status=PASS\n"
           << "ordinary_verifier_unmodified=true\n"
           << "public_TG_equals_A_plus_D=true\n"
           << "fresh_message_absent_from_ordinary_queries=true\n"
           << "untouched_fresh_forgery=ACCEPTED\n"
           << "changed_message_control=REJECTED\n"
           << "altered_signature_control=REJECTED\n"
           << "ground_truth_consulted=false\n";
    std::cout << "VERIFY: PASS untouched=ACCEPT changed-message=REJECT altered-signature=REJECT\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "VERIFY: FAIL: " << e.what() << "\n";
    return 1;
  }
}

