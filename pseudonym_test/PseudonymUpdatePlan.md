# Plan: Bring PseudonymBBS.js into Conformance with the Current Draft

Target spec: [draft-irtf-cfrg-bbs-per-verifier-linkability.md](https://github.com/cfrg/draft-irtf-cfrg-bbs-pseudonyms/blob/main/draft-irtf-cfrg-bbs-per-verifier-linkability.md)

Files in scope: `lib/PseudonymBBS.js`, `lib/BlindBBS.js` (exports only), `pseudonym_test/`, a new `NymTestGeneration/` directory, and `examples/pseudonym/walkthroughSimple.js`.

## Current State

- **Signing is broken.** All 12 sign tests (SHA-256 and SHAKE-256) fail. `BlindSignWithNym` still calls the old `FinalizeBlindSign(SK, PK, B, gens, blindGens, header, api_id)`. BlindBBS now has `FinalizeBlindSign(SK, B, api_id)`, and the domain is computed inside `B_calculate`.
- **Everything else passes, but only against old vectors.** The commit, VerifyFinalize, proof generation and proof verification tests all pass against the existing fixtures. Every one of these vectors will change once the code conforms.
- **Two design gaps compared with the spec:**
  - The code uses the old index-array API rather than DISCLOSE/HIDE/COMMIT disclosures.
  - Messages are plain hex with no `[flag, value]` form. `messages_to_scalars` is imported from `BBS.js` instead of `BlindBBS.js`.

## 1. Spec Problems to Settle First

Some of these change the bytes in the test vectors, so they need decisions before any vectors are generated.

1. **The header binding is lost in BlindSignWithNym.**
   - Step 10 computes `combined_header = header || I2OSP(N, 8)` after `B_calculate` (step 6), and nothing uses it.
   - `B_calculate` now computes the domain, so the signature no longer binds `N`.
   - The signature also wouldn't verify, because VerifyFinalizeWithNym uses `combined_header`.
   - **Fix:** pass `combined_header` into `B_calculate`.
   - GB **DONE**: Fixed spec.
2. **Generator count in BlindSignWithNym.** Step 2 creates `M` blind generators. It should create `M + 1` (Q_2 plus J_1..J_M), which matches Blind BBS and VerifyFinalizeWithNym's `M + N + 1`.
   - GB  **DONE**: fixed spec.
3. **Message counting in ProofVerifyWithNym.**
   - `total_msgs_no = proof_msgs_no - 1` still counts the N nym secrets.
   - Read literally, `message_disclosures` would need N trailing HIDE entries.
   - **Recommendation:** use `total_msgs_no = proof_msgs_no - 1 - length_nym_vector`, with `total_msgs_no - issuer_known_messages_no + N + 1` blind generators.
   - GB **DONE**: fixed spec, used N = length_nym_vector for  blind generators.
4. **The verifier never checks that the nym positions stay hidden.** If a disclosed or committed index falls among the last N, then `hats[-N]` are not the nym responses. Add this check to CoreProofVerifyWithNym.
5. **The api_id strings disagree.** The ProofGen and ProofVerify sections give `BLIND_H2G_HM2S_` and `H2G_HM2S_`, copied from Blind BBS. The interface section gives `H2G_HM2S_PSEUDONYM_`. Use the PSEUDONYM form throughout; the tests already do.
   - GB **DONE**: fixed.
6. **What ProofGenWithNym returns.**
   - The core operation returns `[proof, pseudonym, add_zkp_info]`.
   - The top-level operation returns `(proof_with_add_zkp_info, pseudonym)`. GB **DONE**: fixed.
   - BlindProofGen currently returns only `proof`. --> Blind BBS Code needs to return [proof, add_zkp_info], need to fix test vector generation and verification. See section 2a.
7. **Smaller issues:**
   - `N` means both the commitment count and the nym vector length in CoreProofGenWithNym.
   - CoreProofGenWithNym writes `messages[idx]` where it should write `proof_scalars[idx]`.
   - `PseudonymProofInit` claims to return "three G1 elements".
   - The test-vector templates still use singular `proverNym`/`nym_secret`, `revealedMessages` maps, and `e_tilde` (BlindBBS's trace writes `e_Tilde`). They need updating to whatever fixture format is chosen.

## 2. Prerequisite Changes to lib/BlindBBS.js

These must not change behaviour.

- Export `B_calculate`, `proof_to_octets` and `octets_to_proof`. These are currently module-private. BlindBBS already imports BBS's `octets_to_proof` as `bbs_octets_to_proof`.
- Optional: remove the timing `console.log` calls in `Commit` and `CoreCommit`.
- Re-run `blind_test` to confirm nothing changed.

## 2a. Blind BBS: BlindProofGen Returns `[proof, add_zkp_info]`

This changes the public API. Only `BlindTestGeneration/proofTestGen.js` and `blind_test/proofGenTest.js` call `BlindProofGen`.

### lib/BlindBBS.js
- `CoreProofGen` already builds and returns `[proof, add_zkp_info]`. `BlindProofGen` currently discards `add_zkp_info` (`return proof;`). Change it to `return [proof, add_zkp_info];`.
- Update the JSDoc `@returns` and remove the TODO there.
- Depends on section 2: `octets_to_proof` must be exported for the verification test below.

### Fixture Format
Add a top-level field, named as in the spec so the draft templates can reference it directly:

```json
"add_zkp_info": {
  "committed_message_scalars": ["<32-byte hex>", "..."],
  "commitment_rands": ["<32-byte hex>", "..."]
}
```

- Cases without COMMIT disclosures get empty arrays, so every proof fixture has the same shape.
- The array order is the proof's commitment order: issuer COMMIT messages first, then blind COMMIT messages, each ascending.
- `commitment_rands` duplicates `trace.randomScalars.s_i`. That's deliberate: the trace is informational, while `add_zkp_info` is an operation output.

### BlindTestGeneration/proofTestGen.js
- Destructure `const [proof, add_zkp_info] = await BlindProofGen(...)`.
- Write `proofFixture.add_zkp_info`, with both arrays converted by `numberToHex(x, 32)`.
- The inputs don't change. **Regression anchor:** every regenerated `proof` must be byte-identical to the current `blind_test/fixture_data` values. Only the new field should differ.
- Copy the outputs into `blind_test/fixture_data/*/proof/`.

### blind_test/proofGenTest.js
- Destructure the new return value and keep the existing `proof` assertion.
- Add `assert.deepEqual` of the hex-converted `add_zkp_info` against `proofFixture.add_zkp_info`.

### blind_test/proofVerification.js
After `BlindProofVerify` succeeds, check `add_zkp_info` against the proof. In practice the prover does this when feeding an external ZKP. The verifier never sees `add_zkp_info`.

1. `N = add_zkp_info.commitment_rands.length`. Assert that N equals the number of COMMIT entries in `messageDisclosures` + `blindMessageDisclosures`, and equals `committed_message_scalars.length`.
2. Use `octets_to_proof(proof, N)` to get the commitments `C_1..C_N`.
3. Get `(Y_0, Y_1) = prepareGenerators(2, 'COM_DIS_' + api_id)`. For each i, assert `C_i == Y_0 * s_i + Y_1 * m_i`, where `s_i` and `m_i` come from `add_zkp_info`.
4. Assert that `committed_message_scalars` equals `Blind.messages_to_scalars` of the COMMIT messages (issuer first, then blind) taken from `sigInfo`. This ties the scalars to the actual signed messages.
5. Skip steps 2–4 when N is 0.

### blind_test/CDproofVerification.js (stale)
- It imports `CD_BlindProofVerify`, which no longer exists, and filters for `proof009ComDis.json`, which also doesn't exist.
- `proofVerification.js` already verifies proof009–011, and will now also check their openings.
- Recommendation: delete this file.

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
- Read the BBS proof length from the 8-byte prefix, and count messages as decided in item 3 of section 1.
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
  - A committed-disclosure check modelled on `blind_test/CDproofVerification.js`.
  - Negative cases: wrong `context_id`, tampered pseudonym, wrong `length_nym_vector`, a disclosed nym index, and a bad `message_disclosures` length.
- **Fixtures and docs:**
  - Copy the generated outputs into `pseudonym_test/fixture_data`.
  - Refresh `fixture_data/bls12-381-shake-256/README.md` and `PseudonymTestOverview.md`.
  - Update `examples/pseudonym/walkthroughSimple.js` to the new API.

## Order of Work

1. Settle the open decisions (below).
2. Add the BlindBBS exports, then run the Blind tests.
3. Change the BlindProofGen return value (section 2a). Regenerate the Blind proof vectors, confirm the proofs are unchanged, then update the Blind tests.
4. Rewrite PseudonymBBS.js.
5. Generate the SHA-256 vectors and check the regression anchors.
6. Generate the SHAKE-256 vectors.
7. Update the tests and copy the fixtures.
8. Update the example and docs.

## Open Decisions

- [ ] **Section 1, items 1 and 2** (combined header, M + 1 blind generators): fix in code and in the draft?
- [ ] **Section 1, item 3:** should the verifier's `message_disclosures` cover the nym slots? Recommendation: no.
- [ ] **Return shapes:** should `ProofGenWithNym` return `add_zkp_info`? Should `VerifyFinalizeWithNym` follow the spec, or keep `[valid, nym_secrets]`?
- [ ] **Fixture field names:** keep plural `proverNyms`/`nym_secrets`, and update the draft's templates to match?
