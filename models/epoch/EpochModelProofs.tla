------------------------- MODULE EpochModelProofs -------------------------
EXTENDS EpochModel, Naturals
\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

(***************************************************************************
Proof entrypoint for EpochModel.

This is intentionally a very small, starter TLAPS proof: it shows how to turn
an existing model into a proof obligation and discharge it with TLAPS.

Notes:
- These ASSUME clauses are the "type" assumptions that TLC gets implicitly via
  the concrete constant assignments in the *.cfg files.
- We start with proving that Init implies TypeOK.
***************************************************************************)

THEOREM InitImpliesTypeOK ==
  ASSUME
    /\ NCPUS \in Nat
    /\ MaxEpoch \in Nat /\ MaxEpoch >= 1
    /\ UsePublishedEpochForReader \in BOOLEAN
    /\ UsePublishedEpochForRetire \in BOOLEAN
  PROVE Init => TypeOK
PROOF
  BY DEF Init, TypeOK, CPUS, ObjStates

=============================================================================
