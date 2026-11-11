# Pseudonym (Nym) Test Vector Generation

Scripts that generate the BBS pseudonym test vectors for both ciphersuites from
the input files in `inputs/`. Results are written to `outputs/` (gitignored)
with the same directory layout.

Run from the repository root, in this order:

```
node NymTestGeneration/generatorsTestGen.js
node NymTestGeneration/nymCommitTestGen.js
node NymTestGeneration/nymSignTestGen.js
node NymTestGeneration/nymProofTestGen.js
```

`nymProofTestGen.js` reads the signature outputs named by each proof input's
`signatureFile`, so run `nymSignTestGen.js` first.

The scripts double as self checks:

- `nymSignTestGen.js` runs `VerifyFinalizeWithNym` on each signature, which
  throws if the signature is invalid, and records the resulting `nym_secrets`.
- `nymProofTestGen.js` runs `ProofVerifyWithNym` on each proof and throws if
  the result differs from the input's `result.valid`.

## Cases

| Signature | Notes |
|-----------|-------|
| 001–004 | 1 prover nym, with and without signer and blind messages |
| 005–006 | 10 prover nyms |
| 007 | 1 prover nym, mixed RAW and HASH messages |

| Proof | Signature | Notes |
|-------|-----------|-------|
| 001–007 | 004 | DISCLOSE/HIDE combinations |
| 008 | 004 | COMMIT on signer messages |
| 009 | 004 | COMMIT on blind messages |
| 010 | 004 | COMMIT on both |
| 011 | 007 | COMMIT on both, mixed RAW and HASH messages |
| 101–104 | 006 | 10 nym secrets, DISCLOSE/HIDE combinations |
| 105 | 006 | 10 nym secrets, COMMIT on both |

The 1000 nym secret cases from `pseudonym_test/fixture_data` are not included.
