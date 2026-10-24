# Clean-room provenance

The executable model in `../reproduce-all-rows.py` is an unchanged copy of the
sealed fresh-context independent-v2 implementation. It was developed from the
frozen paper and sealed neutral specification reviews, without reading or
copying the delivered attack program, the primary implementation, or official
HBGS source code. The retained `../evidence/evidence.json` is likewise an
unchanged copy of the sole sealed independent-v2 evidence file.

The wrapper, evidence validator, documentation, and reference summaries in
this public package were written for publication. They do not alter the
clean-room model or evidence and do not execute target code.

No upstream source file is redistributed in this package. The official HBGS
repository is cited and pinned for provenance only; its University of Surrey
BSD-style source-file license and bundled Picnic MIT license remain with that
source.
