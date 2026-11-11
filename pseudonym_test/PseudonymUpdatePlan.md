# Plan: Bring PseudonymBBS.js into Conformance with the Current Draft

Target spec: [draft-irtf-cfrg-bbs-per-verifier-linkability.md](https://github.com/cfrg/draft-irtf-cfrg-bbs-pseudonyms/blob/main/draft-irtf-cfrg-bbs-per-verifier-linkability.md)

The code, test-vector generation (`NymTestGeneration/`), tests, fixtures, example and docs have all been updated. What remains below is mostly for the draft itself.

## 1. Remaining Spec Problems

Fixed in the draft:
- The nym-position checks (CoreProofGenWithNym step 8, CoreProofVerifyWithNym steps 18–19).
- The use of `N` for two counts in CoreProofGenWithNym.
- `messages` replaced by `proof_scalars` throughout CoreProofGenWithNym.
- CoreProofGenWithNym's `length_nym_secrets` in step 4, `init_random_scalars` in step 8, the `add_zkp_info` output, and the commas in its signature line.
- ProofGenWithNym's step numbering.
- PseudonymProofInit's inputs are now described as vectors of scalars, and its output's middle item as an octet string.
- The missing commas in ProofGenWithNym step 12 and the PseudonymProofVerifyInit signature line.
- `api_id` is now a Parameter of PseudonymProofInit and PseudonymProofVerifyInit.
- The output descriptions of PseudonymProofInit and PseudonymProofVerifyInit (a triple: G1 element, octet string, G1 element). Nit: both still have a double space in "G1  group".

1. **Test-vector templates** still use singular `proverNym`/`nym_secret`, `revealedMessages` maps, and `e_tilde`. They should match the fixture format: plural `proverNyms`/`nym_secrets`, `[flag, value]` messages, DISCLOSE/HIDE/COMMIT disclosures, and `e_Tilde`.

## 2. Remaining Follow-ups

- **Disclosed nym index negative test:** `ProofVerifyWithNym` gives a caller no way to aim a disclosure at a nym position, so only the check inside `CoreProofVerifyWithNym` guards it. A direct test of the core function would cover it.
- **1000-nym cases:** optional. They were removed from the fixtures and are not in `NymTestGeneration/inputs/`. The old versions are in git history.
- **Pre-existing lint errors** in `pseudonym_test/nym_context_gen.js`.
- The default `npx mocha` run does not include `pseudonym_test/`. Run `npx mocha pseudonym_test` explicitly.

## Decisions Made

- **VerifyFinalizeWithNym** follows the spec: it returns `nym_secrets` and throws on INVALID.
- **CommitWithNym** no longer returns `length_prover_nym_vector`.
- **ProofGenWithNym** returns `[proof, pseudonym, add_zkp_info]`.
- **Fixture field names** are plural `proverNyms`/`nym_secrets`. The draft's templates should be updated to match (see 1.1).
