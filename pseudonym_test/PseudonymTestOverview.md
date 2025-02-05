# Proposed BBS Pseudonym Test Cases/Vectors

## Prover Nym and Arbitrary Commitments

Exercises the API call:

(commitment_with_proof, secret_prover_blind) = **Commit**(committed_messages, prover_nym, api_id)

1. valid no committed messages, prover_nym, creates commitment with proof, secret prover blind **DONE**
2. valid multiple committed messages, prover_nym, creates commitment with proof, secret prover blind **DONE**

## Blind Sign with Nym

Exercises the API call:

blind_sig = **BlindSignWithNym**(SK, PK, commitment_with_proof, signer_nym_entropy, header, messages)

*Note* this is the updated *BlindSignWithNym(...)* API that takes *signer_nym_entropy* as a parameter.

1. valid no prover committed messages only committed prover_nym, no signer messages signature
2. valid multi prover committed messages and committed prover_nym, no signer messages signature
3. valid no prover committed messages only committed prover_nym, multiple signer messages signature
4. valid multiple signer and committed prover_nym, and prover committed messages signature

## Finalize Nym Secret and Verify

Exercises the API call:

nym_secret = **Finalize**(PK, signature, header, messages, committed_messages, prover_nym, signer_nym_entropy, secret_prover_blind)

*Note*: hopefully we'll have a more descriptive name for the above API. Should be able to combine this into the same test vector file as the signature test vector files.

1. Use "no prover committed messages only committed prover_nym, no signer messages signature" verify and compute *nym_secret*.
2. Use "valid multi prover committed messages and committed prover_nym, no signer messages signature" verify and compute *nym_secret*.

## Proof Generation with Nym

Exercises the API call:

(proof, Pseudonym) = **ProofGenWithNym**(PK, signature, header, ph, nym_secret, context_id, messages, committed_messages, disclosed_indexes, disclosed_commitment_indexes, secret_prover_blind)

*Note* additional information over blind proof generation. Inputs: *nym_secret*, *context_id*, output: *pseudonym*.

1. valid all prover committed messages and signer messages revealed proof
2. valid half prover committed messages and all signer messages revealed proof
3. valid all prover committed messages and half signer messages revealed proof
4. valid half prover committed messages and half signer messages revealed proof
5. valid no prover committed messages and half signer messages revealed proof
6. valid half prover committed messages and no signer messages revealed proof
7. valid no prover committed messages and no signer messages revealed proof
