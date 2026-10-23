# Reproducer

This standard-library Python package replays the full claimed
`n=m=1024` BN254/BabyJubJub/MiMC91 profile from revision 2 of ePrint
2025/1174. From the attack directory, run:

```bash
./reproducer/reproduce.sh --quick
./reproducer/reproduce.sh --full
```

Quick mode independently validates the retained 1,024-key public evidence,
including every BabyJubJub curve equation and MiMC91 key hash. Full mode
regenerates all KGO outputs, performs the adaptive 254-pair orientation,
executes SMA Equation 15 and KZG Equation 17, checks the honest ccGro16 and
CPlink witness relations, and runs three negative controls. Full mode normally
takes about one minute on one CPU worker.

The implementation is deliberately scoped. Group elements in the SMA/KZG
replay are public-SRS coefficient vectors. The program does not emit concrete
ccGro16 or CPlink proof objects and does not call a complete author LRS
verifier or codec; none was located in the published artifact. Its composite
acceptance flag is a paper-specification certificate that combines the
executed SMA/KZG checks with correctness of the two honest-witness components.

`upstream/mimc.circom` is copied without modification from author-source
commit `b312e41b069857209eb680c156692bb5d2b456b4`. Its embedded GPLv3 notice is
preserved. The rest of this reproducer uses only the Python standard library.
