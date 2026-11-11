# Plan: Bring PseudonymBBS.js into Conformance with the Current Draft

Target spec: [draft-irtf-cfrg-bbs-per-verifier-linkability.md](https://github.com/cfrg/draft-irtf-cfrg-bbs-pseudonyms/blob/main/draft-irtf-cfrg-bbs-per-verifier-linkability.md)

Files in scope: `lib/PseudonymBBS.js`, `lib/BlindBBS.js` (exports only), `pseudonym_test/`, a new `NymTestGeneration/` directory, and `examples/pseudonym/walkthroughSimple.js`.

## Current State

- **Signing is broken.** All 12 sign tests (SHA-256 and SHAKE-256) fail. `BlindSignWithNym` still calls the old `FinalizeBlindSign(SK, PK, B, gens, blindGens, header, api_id)`. BlindBBS now has `FinalizeBlindSign(SK, B, api_id)`, and the domain is computed inside `B_calculate`.
- **Everything else passes, but only against old vectors.** The commit, VerifyFinalize, proof generation and proof verification tests all pass against the existing fixtures. Every one of these vectors will change once the code conforms.
- **Two design gaps compared with the spec:**
  - The code uses the old index-array API rather than DISCLOSE/HIDE/COMMIT disclosures.
  - Messages are plain hex with no `[flag, value]` form. `messages_to_scalars` is imported from `BBS.js` instead of `BlindBBS.js`.

## 1. Remaining Spec Problems

1. **The verifier never checks that the nym positions stay hidden.** If a disclosed or committed index falls among the last N, then `hats[-N]` are not the nym responses. Add this check to CoreProofVerifyWithNym (and the matching check to CoreProofGenWithNym).
2. **Smaller issues:**
   - `N` means both the commitment count and the nym vector length in CoreProofGenWithNym.
   - CoreProofGenWithNym writes `messages[idx]` where it should write `proof_scalars[idx]`.
   - `PseudonymProofInit` claims to return "three G1 elements".
   - The test-vector templates still use singular `proverNym`/`nym_secret`, `revealedMessages` maps, and `e_tilde` (BlindBBS's trace writes `e_Tilde`). They need updating to whatever fixture format is chosen.

## 2. Prerequisite Changes to lib/BlindBBS.js

These must not change behaviour.

- Export `B_calculate` and `proof_to_octets`. These are currently module-private. (`octets_to_proof` is already exported.)
- Optional: remove the timing `console.log` calls in `Commit` and `CoreCommit`.
- Re-run `blind_test` to confirm nothing changed.

## 3. Changes to lib/PseudonymBBS.js

### General
- Import `messages_to_scalars` from `BlindBBS.js`.
- Add `GEN_TRACE_OBJECT` and an exported `traceInfo`, as BlindBBS does.
- Rename the helpers to the spec names:
  - `NymProofInit` becomes `PseudonymProofInit`.
  - `NymProofVerifyInit` becomes `PseudonymProofVerifyInit`.
  - `ProofWithNymChallengeCalculate` becomes `ProofWithPseudonymChallengeCalculate`.

### CommitWithNym
- Already close to the spec. Switch to flagged messages.
- It returns an extra `length_prover_nym_vector` that the spec doesn't. Recommendation: drop it. This is an API change.

### BlindSignWithNym
- Create `L + 1` generators and `M + 1` blind generators, then call `deserialize_and_validate_commit`.
- Call `Blind.B_calculate(..., combined_header)`, add `J_M * signer_nym_entropy`, then call `FinalizeBlindSign(SK, B, api_id)`.
- Delete `B_calculate_with_nym`. It also creates a `new Error` that is never thrown.
- Record the trace value of B after the entropy is added. Blind BBS's own B trace records it before.

### VerifyFinalizeWithNym
- The logic already matches. Switch to flagged messages.
- It returns `[valid, nym_secrets]`, while the spec returns `nym_secrets` or INVALID. Recommendation: follow the spec and throw on INVALID.

### ProofGenWithNym
- New signature:
  `(PK, signature, header, ph, nym_secrets, context_id, messages, blind_messages, message_disclosures, blind_message_disclosures, secret_prover_blind, api_id, rand_scalars)`.
- Validate the inputs as BlindProofGen does, and build the indexes with `get_combined_idxs`.
- Build the scalars with `prepare_parameters(..., L + 1, M + N + 1, ...)` and append `nym_secrets`.
- Return the proof, pseudonym and `add_zkp_info` as the corrected spec does, matching `BlindProofGen`'s `[proof, add_zkp_info]`.

### CoreProofGenWithNym
- Get `Y_0` and `Y_1` from `create_generators(2, "COM_DIS_" || api_id)`.
- Check that the indexes are strictly ascending, in range, disjoint, and not on a nym position.
- Draw `5 + U + 2*Nc` random scalars. Pass the first `5 + U` and `combined_header` to `ProofInit`.
- Take the nym random scalars from `init_rands[5 + U - Nn, 5 + U)`.
- Compute `C_i` and `C~_i`, the challenge, `ProofFinalize`, and `s^_i`. Then call `Blind.proof_to_octets` and build `add_zkp_info`.
- Fill the trace object.

Here `Nc` is the number of committed-disclosure messages and `Nn` is the nym vector length. The code should use distinct names for them.

### ProofWithPseudonymChallengeCalculate
- Remove `context_id` from `c_arr`. The current code appends it, but the spec doesn't.
- Append `commitment_arr = (N, ci_1, C_1, C~_1, ...)`, then the presentation header as before.

### ProofVerifyWithNym
- New signature:
  `(PK, proof, header, ph, pseudonym, context_id, length_nym_vector, issuer_known_messages_no, disclosed_messages, message_disclosures, api_id)`.
- Read the BBS proof length from the 8-byte prefix. Count messages as the corrected spec does: `total_msgs_no = proof_msgs_no - 1 - length_nym_vector`, with `total_msgs_no - issuer_known_messages_no + length_nym_vector + 1` blind generators.
- Return `false` rather than throwing.

### CoreProofVerifyWithNym
- Deserialize with `Blind.octets_to_proof(proof, Nc)`, compute `C^_i`, then call `PseudonymProofVerifyInit` with `hats.slice(-Nn)`.
- Check that the pseudonym isn't the identity point, inside a try/catch.
- Remove the stray `console.log` calls.

### No Change Needed
- `hash_to_curve_g1` (DST = api_id) and the polynomial evaluation already match the spec.

### Incidental Bug
- In `ProofGenWithNym`, the commitment-index bound check tests against `L` instead of `M`.

## 4. Test-Vector Generation: New NymTestGeneration/ Directory

Modelled on `BlindTestGeneration/`.

### Layout
- `inputs/{bls12-381-sha-256,bls12-381-shake-256}/{nymCommit,nymSignature,nymProof}/`
- `outputs/` with the same structure. It is already gitignored by `*/outputs/*`.

### Scripts
- `nymCommitTestGen.js`
- `nymSignTestGen.js`: commits with the seeded RNG, calls `BlindSignWithNym`, then `VerifyFinalizeWithNym`. This fills in `nym_secrets` and doubles as a self-check.
- `nymProofTestGen.js`: loads the matching signature output through `signatureFile`, generates the proof, pseudonym and trace, then runs `ProofVerifyWithNym` as a self-check. This self-check is an improvement over the Blind generator.

### Input Format
- Follow the newer Blind BBS style: `[flag, hex]` messages, `proverNyms[]`, `signer_nym_entropy`, `context_id`, `signatureFile`, and `messageDisclosures`/`blindMessageDisclosures`.
- Seed the values from the existing fixtures (same keys, messages, nyms, entropy and context_id).

### Regression Anchors
These values should come out unchanged, so they check the refactor:
- `commitmentWithProof`, as long as all flags are HASH and `CoreCommit` is unchanged.
- Every `pseudonym` value, because the polynomial and OP are unchanged.

### Cases
- Keep cases 001–007 and the 10-nym cases 101–104.
- Add committed-disclosure cases (COMMIT on issuer messages, on blind messages, and on both), like Blind BBS's proof008–011.
- Add a case that mixes RAW and HASH messages.
- Leave the 1000-nym cases (105, 110 and `supplement/`) optional and excluded from normal runs.

### Generators
- Regenerate `generators.json` for the spec's Generators and Blind Generators sections.

## 5. Test and Documentation Updates

- **Rewrite against the new fixtures and APIs:** all six tests in `pseudonym_test/`. The proof tests should load the signature through `signatureFile`, as `blind_test/proofGenTest.js` does.
- **New tests:**
  - Committed-disclosure checks on `add_zkp_info`, modelled on those in `blind_test/proofVerification.js`.
  - Negative cases: wrong `context_id`, tampered pseudonym, wrong `length_nym_vector`, a disclosed nym index, and a bad `message_disclosures` length.
- **Fixtures and docs:**
  - Copy the generated outputs into `pseudonym_test/fixture_data`.
  - Refresh `fixture_data/bls12-381-shake-256/README.md` and `PseudonymTestOverview.md`.
  - Update `examples/pseudonym/walkthroughSimple.js` to the new API.

## Order of Work

1. Settle the open decisions (below).
2. Add the BlindBBS exports, then run the Blind tests.
3. Rewrite PseudonymBBS.js.
4. Generate the SHA-256 vectors and check the regression anchors.
5. Generate the SHAKE-256 vectors.
6. Update the tests and copy the fixtures.
7. Update the example and docs.

## Open Decisions

- [ ] **VerifyFinalizeWithNym return shape:** follow the spec (`nym_secrets` or INVALID), or keep `[valid, nym_secrets]`?
- [ ] **Fixture field names:** keep plural `proverNyms`/`nym_secrets`, and update the draft's templates to match?
