# Plan: Pseudonym Draft Test-Vector Templates

Goal: populate the test-vector section headings of the pseudonym draft from each fixture's `caseName`, as the Blind BBS draft now does, and bring the templates, fixtures and population scripts up to date.

Repos:
- This library: caseNames and fixture generation (`NymTestGeneration/`).
- Pseudonym draft, local copy at `/home/greg/Greg_Work/SecurityPrivacy/draft-irtf-cfrg-bbs-pseudonyms/`: `draft-irtf-cfrg-bbs-per-verifier-linkability.md` and `fixtures/`.
- Reference: the Blind BBS draft repo, `fixtures/index.ts` and `fixtures/fetchFixtures.ts` (commits 40ef42e and ecd383a).

## How the Blind BBS Repo Does It

- **Headings come from the fixtures.** Each test-vector heading is written as `#### {{ # $proofFixtures.bls12-381-sha-256.proof001.caseName }}`.
- **`index.ts` changes:**
  - Its regex accepts either `{{` or `{{ #`.
  - Headings are inserted without quotes and without the 72-column wrapping.
  - A recursive `formatValue` prints nested arrays, so `[flag, hex]` messages come out correctly.
- **`fetchFixtures.ts`** is the same as the pseudonym repo's apart from the fixture directory names and some lines commented out.
- **caseNames** are in Title Case, for example "Valid Half Blind Messages and All Signer Messages Revealed Proof".

## Where the Pseudonym Repo Is Today

- **Headings** are typed by hand, and five proof sections share the same heading ("valid all prover committed messages and signer messages revealed proof").
- **Templates** use the old fixture format: `proverNym`, `nym_secret`, `committedMessages`, `revealedMessages`/`revealedCommittedMessages` maps, `trace.random_scalars.e_tilde`, and per-proof `signature`/`commitmentWithProof`.
- **Case coverage:** the draft covers only commits 001–002, signatures 001–004 and proofs 001–007. Its generator lists are H_0–H_9 and J_0–J_5, with no Y_0/Y_1. The two ciphersuite sections are identical apart from the suite name.
- **Fixture data** is the old set: no signature 007, no proofs 008–011 or 101–105.
- **`index.ts` and `fetchFixtures.ts`:**
  - `index.ts` has no heading support and doesn't handle nested arrays.
  - `fetchFixtures.ts` would drop `commitmentGenerators`, because it only recognises objects that have `caseName`, `MsgGenerators` or `mockedScalars`.
  - It also has a stray `console.log(proofFixtures)`.

## (a) Better caseNames, in `NymTestGeneration/inputs/` (Both Suites)

These are in Title Case to match Blind BBS. Each has to be unique within a suite, because it becomes a section heading. "Blind" means the prover's committed messages and "Signer" means the issuer's messages.

| Case | Proposed caseName |
|---|---|
| nymCommit001 | Valid Zero Blind Messages, One Prover Nym Commitment with Proof |
| nymCommit002 | Valid Multiple Blind Messages, One Prover Nym Commitment with Proof |
| nymCommit003 | Valid Zero Blind Messages, Ten Prover Nyms Commitment with Proof |
| nymCommit004 | Valid Multiple Blind Messages, Ten Prover Nyms Commitment with Proof |
| nymSignature001 | Valid Zero Blind Messages, Zero Signer Messages Signature |
| nymSignature002 | Valid Multiple Blind Messages, Zero Signer Messages Signature |
| nymSignature003 | Valid Zero Blind Messages, Multiple Signer Messages Signature |
| nymSignature004 | Valid Multiple Blind Messages, Multiple Signer Messages Signature |
| nymSignature005 | Valid Zero Blind Messages, Multiple Signer Messages, Ten Nym Secrets Signature |
| nymSignature006 | Valid Multiple Blind Messages, Multiple Signer Messages, Ten Nym Secrets Signature |
| nymSignature007 | Valid Multiple Blind Messages, Mixed RAW and HASH Signer Messages Signature |
| nymProof001 | Valid All Blind Messages and All Signer Messages Revealed Proof |
| nymProof002 | Valid Half Blind Messages and All Signer Messages Revealed Proof |
| nymProof003 | Valid All Blind Messages and Half Signer Messages Revealed Proof |
| nymProof004 | Valid Half Blind Messages and Half Signer Messages Revealed Proof |
| nymProof005 | Valid Zero Blind Messages and Half Signer Messages Revealed Proof |
| nymProof006 | Valid Half Blind Messages and Zero Signer Messages Revealed Proof |
| nymProof007 | Valid Zero Blind Messages and Zero Signer Messages Revealed Proof |
| nymProof008 | Valid Half Blind Messages Revealed, Signer Messages Revealed and Committed Proof |
| nymProof009 | Valid Blind Messages Revealed and Committed, Half Signer Messages Revealed Proof |
| nymProof010 | Valid Blind and Signer Messages Revealed and Committed Proof |
| nymProof011 | Valid Blind and Signer Messages Revealed and Committed, Mixed RAW and HASH Proof |
| nymProof101–104 | Same as 001–004, followed by ", Ten Nym Secrets" |
| nymProof105 | Same as 010, followed by ", Ten Nym Secrets" |

These names match what each case's disclosures actually do. Several of today's names don't: for example, 005's "no prover committed" really means all blind messages are hidden.

Steps:
- Change the names in both suites' inputs, then regenerate.
- Diff the outputs against the current `pseudonym_test/fixture_data`. Only `caseName` should change.
- Re-copy the outputs into `pseudonym_test/fixture_data` and run `npx mocha pseudonym_test`.

## (b) Rewrite the Draft's Test Vectors Section

Each suite section would contain:

1. **Generators:** `api_id`, P1, Q1, and H_0–H_10 (L + 1 = 11).
2. **Blind Generators:** J_0–J_6 (M + N + 1 = 7).
3. **Committed Disclosure Generators (new):** `api_id`, Y_0 and Y_1.
4. **Commitment with Nym:** the mock RNG seed and DST, then for each case:
   - `{{ # …caseName }}` heading
   - `blindMessages`, `proverNyms`, `proverBlind`
   - Trace: `s_tilde`, `m_tildes`
   - `commitmentWithProof`
5. **Signature with Nym:** for each case:
   - Heading and a "Signature Label"
   - `secretKey`, `publicKey`, `header`, `messages`, `blindMessages`
   - `proverNyms`, `signer_nym_entropy`, `commitmentWithProof`, `proverBlind`
   - Trace: `B`, `domain`
   - `signature`, `nym_secrets`
6. **Proof with Pseudonym:** the mock RNG seed and DST, then for each case:
   - Heading and "Based on signature: `signatureFile`"
   - `signerPublicKey`, `header`, `presentationHeader`, `context_id`
   - `messageDisclosures`, `blindMessageDisclosures`
   - Trace:
     - Random scalars: `r1`, `r2`, `e_tilde`, `r1_tilde`, `r3_tilde`, `m_tilde_scalars`, and `s_i`, `s_tilde_i` for COMMIT cases
     - `Abar`, `Bbar`, `D`, `T1`, `T2`, `C_i`, `C_tilde_i`, `Ut`
     - `domain`, `challenge`
   - `add_zkp_info` (COMMIT cases only)
   - `L`, `pseudonym`, `proof`

**Disclosure format:** print disclosures as a single array (`messageDisclosures = [ "DISCLOSE", "HIDE", … ]`) rather than one line per index. The recursive `formatValue` wraps it, and an empty `blindMessageDisclosures` then prints as `[ ]` instead of `undefined`.

**Which cases go in the draft:** I recommend all of them in both suites (4 commits, 7 signatures, 16 proofs). Implementations then get the 10-nym and committed-disclosure coverage, as Blind BBS has for its committed-disclosure cases. The cost is length: about 27 sections per suite.

**How the templates are written:** because the two suites are identical, write a small one-off script that emits the SHA-256 block from the case list and copies it for SHAKE-256. It would only be used to paste the result into the `.md` once, not on every build. It avoids copy errors across roughly 1,100 template lines. The alternative is to edit the templates by hand, as Blind BBS did.

**Also:** remove the `<!-- **TODO**: Update! -->` comment.

## (c) Update the Test Vectors in the Draft Repo

- Replace `fixtures/fixture_data/{bls12-381-sha-256,bls12-381-shake-256}/` with this library's `pseudonym_test/fixture_data` set, after (a), including `generators.json`.
- Drop `fixture_data/messages.json` and its import, since no template uses it. Blind BBS commented that import out.

## (d) Update `fixtures/index.ts` and `fixtures/fetchFixtures.ts`

- **`index.ts`:** port the Blind BBS version: the regex with `{{ #` heading support, the recursive `formatValue`, and no wrapping for headings. Keep `DRAFT_NAME` as the pseudonym draft.
- **`fetchFixtures.ts`:**
  - Add `input.Y_0` to the leaf detection so `commitmentGenerators` is picked up.
  - Update the interfaces to the new fields: `proverNyms`, `nym_secrets`, `signer_nym_entropy`, `blindMessages`, `context_id`, `pseudonym`, the disclosures, `add_zkp_info` and the new trace fields.
  - Remove the `console.log` and the `messages` import.
- **Overwrite risk:** both repos' `index.ts` overwrite the draft in place, which replaces the templates with populated values. Blind BBS has an unused `outPath` (`../temp/output.md`, gitignored). Write there by default, or take a command-line flag, so running the script locally can't lose the templates by accident. Whatever the build or CI does should keep working; check how Blind BBS publishes before changing this.
- **Check:** run `npm run populate-fixtures` and confirm that no `{{` is left, that there are no `undefined` values, and that every line is at most 72 columns. Then run `make` to make sure the draft builds.

## Order of Work

1. (a) Rename the caseNames in this library, regenerate, re-copy and re-test.
2. (d) Port `index.ts` and `fetchFixtures.ts` in the draft repo.
3. (c) Copy the fixtures into the draft repo.
4. (b) Generate and paste the templates, populate into a temporary output, check, and build.

## Open Decisions

- [ ] Are the proposed caseNames acceptable?
- [ ] Should the draft include all 27 cases per suite, or a subset?
- [ ] Should the templates be generated by a script or written by hand?
- [ ] Should `index.ts` write to a separate output file by default?
