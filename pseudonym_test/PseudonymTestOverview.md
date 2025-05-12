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

**DONE**

## Finalize Nym Secret and Verify

Exercises the API call:

nym_secret = **Finalize**(PK, signature, header, messages, committed_messages, prover_nym, signer_nym_entropy, secret_prover_blind)

*Note*: hopefully we'll have a more descriptive name for the above API. Should be able to combine this into the same test vector file as the signature test vector files. Uses signature test vectors with nym_secret added to them. **DONE**

## Proof Generation with Nym

Exercises the API call:

(proof, Pseudonym) = **ProofGenWithNym**(PK, signature, header, ph, nym_secret, context_id, messages, committed_messages, disclosed_indexes, disclosed_commitment_indexes, secret_prover_blind)

*Note* additional information over blind proof generation. Inputs: *nym_secret*, *context_id*, output: *pseudonym*. **DONE**

1. valid all prover committed messages and signer messages revealed proof
2. valid half prover committed messages and all signer messages revealed proof
3. valid all prover committed messages and half signer messages revealed proof
4. valid half prover committed messages and half signer messages revealed proof
5. valid no prover committed messages and half signer messages revealed proof
6. valid half prover committed messages and no signer messages revealed proof
7. valid no prover committed messages and no signer messages revealed proof

## Performance Testing with Large Nym Secrets Vector

Timings for 1000 Nym Secrets, JavaScript

CommitWithNym:prepareGenerators time: 1595
Commit time = 2263ms, proof time = 3197ms
CommitWithNym:CoreCommit time: 5464

CommitWithNym:prepareGenerators time: 1564
Commit time = 2280ms, proof time = 3229ms
CommitWithNym:CoreCommit time: 5513

CommitWithNym:prepareGenerators time: 1577
Commit time = 2259ms, proof time = 3202ms
CommitWithNym:CoreCommit time: 5465

BlindSignWithNym:prepareGenerators-Blind time: 1583
BlindSignWithNym:deserialize_and_validate_commit: 3119
BlindSignWithNym:rest of blind sign: 878

BlindSignWithNym:prepareGenerators-Blind time: 1589
BlindSignWithNym:deserialize_and_validate_commit: 3222
BlindSignWithNym:rest of blind sign: 901

BlindSignWithNym:prepareGenerators-Blind time: 1546
BlindSignWithNym:deserialize_and_validate_commit: 3062
BlindSignWithNym:rest of blind sign: 870

VerifyFinalizeWithNym:prepare_parameters (including gens): 1608
VerifyFinalizeWithNym:verify (from BBS): 3258

VerifyFinalizeWithNym:prepare_parameters (including gens): 1687
VerifyFinalizeWithNym:verify (from BBS): 3380

VerifyFinalizeWithNym:prepare_parameters (including gens): 1574
VerifyFinalizeWithNym:verify (from BBS): 3203

### Proof Generation in Indexed Group Case:

ProofGenWithNym:prepare_parameters (including gens): 1578
ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): 5400
ProofGenWithNym:CoreProofGenWithNym:NymProofInit: 6061
ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): 117

ProofGenWithNym:prepare_parameters (including gens): 1584
ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): 5371
ProofGenWithNym:CoreProofGenWithNym:NymProofInit: 6015
ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): 120

ProofGenWithNym:prepare_parameters (including gens): 1595
ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): 5855
ProofGenWithNym:CoreProofGenWithNym:NymProofInit: 6056
ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): 123

### Proof Generation with Polynomial Evaluation Case:

ProofGenWithNym:prepare_parameters (including gens): 1589
ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): 5408
ProofGenWithNym:CoreProofGenWithNym:NymProofInit: 8
ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): 120

ProofGenWithNym:prepare_parameters (including gens): 1599
ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): 5882
ProofGenWithNym:CoreProofGenWithNym:NymProofInit: 7
ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): 117

ProofGenWithNym:prepare_parameters (including gens): 1781
ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): 5472
ProofGenWithNym:CoreProofGenWithNym:NymProofInit: 8
ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): 119

### Proof Generation with Inner Product Case:

ProofGenWithNym:prepare_parameters (including gens): 1601
ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): 5519
ProofGenWithNym:CoreProofGenWithNym:NymProofInit: 22
ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): 133

ProofGenWithNym:prepare_parameters (including gens): 1587
ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): 5418
ProofGenWithNym:CoreProofGenWithNym:NymProofInit: 22
ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): 128

ProofGenWithNym:prepare_parameters (including gens): 1589
ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): 5399
ProofGenWithNym:CoreProofGenWithNym:NymProofInit: 22
ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): 118

### Proof Verification Indexed Group Case

ProofVerifyWithNym:prepare_parameters (including gens): 1652
ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : 3330
ProofVerifyWithNym:CoreProofVerifyWithNym:NymProofVerifyInit : 4004

ProofVerifyWithNym:prepare_parameters (including gens): 2101
ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : 3269
ProofVerifyWithNym:CoreProofVerifyWithNym:NymProofVerifyInit : 3998

ProofVerifyWithNym:prepare_parameters (including gens): 1620
ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : 3722
ProofVerifyWithNym:CoreProofVerifyWithNym:NymProofVerifyInit : 3931

### Proof Verification Polynomial Evaluation Case

ProofVerifyWithNym:prepare_parameters (including gens): 1650
ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : 3278
ProofVerifyWithNym:CoreProofVerifyWithNym:NymProofVerifyInit : 8

ProofVerifyWithNym:prepare_parameters (including gens): 1668
ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : 3309
ProofVerifyWithNym:CoreProofVerifyWithNym:NymProofVerifyInit : 8

ProofVerifyWithNym:prepare_parameters (including gens): 1602
ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : 3274
ProofVerifyWithNym:CoreProofVerifyWithNym:NymProofVerifyInit : 8

### Proof Verification Inner Product Case

ProofVerifyWithNym:prepare_parameters (including gens): 1631
ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : 3334
ProofVerifyWithNym:CoreProofVerifyWithNym:NymProofVerifyInit : 24

ProofVerifyWithNym:prepare_parameters (including gens): 1631
ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : 3268
ProofVerifyWithNym:CoreProofVerifyWithNym:NymProofVerifyInit : 22

ProofVerifyWithNym:prepare_parameters (including gens): 2012
ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : 3352
ProofVerifyWithNym:CoreProofVerifyWithNym:NymProofVerifyInit : 22
