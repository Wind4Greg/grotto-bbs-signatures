# Plan: Bring PseudonymBBS.js into Conformance with the Current Draft

Target spec: [draft-irtf-cfrg-bbs-per-verifier-linkability.md](https://github.com/cfrg/draft-irtf-cfrg-bbs-pseudonyms/blob/main/draft-irtf-cfrg-bbs-per-verifier-linkability.md)

The code, test-vector generation (`NymTestGeneration/`), tests, fixtures, example and docs have all been updated. What remains below is mostly for the draft itself.

## 1. Remaining Spec Problems

1. **The verifier never checks that the nym positions stay hidden.** If a disclosed or committed index falls among the last N, then `hats[-N]` are not the nym responses. The draft should add this check to CoreProofVerifyWithNym, and the matching check to CoreProofGenWithNym. The code already does both.
2. **Smaller issues:**
   - `N` means both the commitment count and the nym vector length in CoreProofGenWithNym. The code uses `Nc` and `Nn`.
   - CoreProofGenWithNym writes `messages[idx]` where it should write `proof_scalars[idx]`.
   - `PseudonymProofInit` claims to return "three G1 elements".
   - The test-vector templates still use singular `proverNym`/`nym_secret`, `revealedMessages` maps, and `e_tilde`. They should match the fixture format: plural `proverNyms`/`nym_secrets`, `[flag, value]` messages, DISCLOSE/HIDE/COMMIT disclosures, and `e_Tilde`.

## 2. Remaining Follow-ups

- **Disclosed nym index negative test:** `ProofVerifyWithNym` gives a caller no way to aim a disclosure at a nym position, so only the check inside `CoreProofVerifyWithNym` guards it. A direct test of the core function would cover it.
- **1000-nym cases:** optional. They were removed from the fixtures and are not in `NymTestGeneration/inputs/`. The old versions are in git history.
- **Pre-existing lint errors** in `pseudonym_test/nym_context_gen.js`.
- The default `npx mocha` run does not include `pseudonym_test/`. Run `npx mocha pseudonym_test` explicitly.

## Decisions Made

- **VerifyFinalizeWithNym** follows the spec: it returns `nym_secrets` and throws on INVALID.
- **CommitWithNym** no longer returns `length_prover_nym_vector`.
- **ProofGenWithNym** returns `[proof, pseudonym, add_zkp_info]`.
- **Fixture field names** are plural `proverNyms`/`nym_secrets`. The draft's templates should be updated to match (see 1.2).
