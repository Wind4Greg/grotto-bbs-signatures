---
title: BBS Signature Guide Theory and Practice
author: Dr. Greg M. Bernstein
date: 2023-10-01
---

# A Guide to BBS Signatures

**Work in Progress**: Not fit for human consumption...

This is the rough outline and notes for a guide to BBS signatures from applications to theoretical underpinnings and security properties.

1. Application Scenarios and Benefits
   1. Verifiable Credentials, Anonymous Credentials (AnonCreds)
      1. Three party model: Issuer, Holder, Verifier
   2. Selective Disclosure
      1. What is it
      2. Examples: CLR
      3. Quick comparison to other high level selective disclosure approaches
      4. Size characteristics of general selective disclosure approaches
   3. Unlinkable signatures (holder supplies "signature proof of knowledge" to verifier instead of original signature from issuer)
      1. Tracking/Linking Threat Model: Verifier-Verifier collusion, Issuer-Verifier collusion
      2. Other signature schemes that provide unlinkability (quick review)
2. Key Theoretical Techniques
   1. Elliptic Curves and Pairings
   2. Sigma Protocols for General Linear Relations for ZKP
   3. Short signatures over multiple messages
      1. Signature Security Properties (review)
      2. Formula and Correctness
      3. Standardization
      4. Proved Properties and Assumptions
   4. Unlinkable Proofs
      1. Security Properties of Signature Proof of Knowledge
      2. Formulas and Correctness
      3. Standardization
3. History and Theoretical Properties
   1. Security Models: Plain, Random Oracle, AGM...
   2. BBS2004 *Short group signatures*
   3. CL2004 *Signature Schemes and Anonymous Credentials from Bilinear Maps*
   4. ASM2006 *Constant-size dynamic k-TAA*
   5. CDL2016 *Anonymous attestation using the strong Diffie-Hellman assumption revisited*
   6. TZ2023 *Revisiting BBS Signatures*
4. Key Supplemental Techniques
   1. ZKP via Sigma Protocols for general linear relations (simplest to most general)
      1. [Schnorr Non-interactive Zero-Knowledge Proof (RFC8235)](https://www.rfc-editor.org/rfc/rfc8235.html), 2017. Provides full details.
      2. CS1997 *Efficient group signature schemes for large groups*
      3. CKY2009 *On the portability of generalized Schnorr proofs*
   2. Fiat-Shamir heuristic: FS1987 *How to prove yourself: Practical solution to identification and signature problems*
   3. Pedersen Commitments: Ped1992 *Non-interactive and information-theoretic secure verifiable secret sharing*

# Applications and Desired Features

## Verifiable Credentials

W3C Verifiable Credentials:

* [Wikipedia: Verifiable Credentials](https://en.wikipedia.org/wiki/Verifiable_credentials)
* [Verifiable Credentials Data Model v2.0 W3C Editor's Draft](https://w3c.github.io/vc-data-model/)
* [Verifiable Credential Data Integrity 1.0 Securing the Integrity of Verifiable Credential Data](https://w3c.github.io/vc-data-integrity/) W3C Candidate Recommendation Snapshot. *Caveat 1*
* [Data Integrity ECDSA Cryptosuites v1.0 Achieving Data Integrity using ECDSA with NIST-compliant curves](https://w3c.github.io/vc-di-ecdsa/) W3C Candidate Recommendation Snapshot. Includes selective disclosure functionality. *Caveat 1*
* [Data Integrity EdDSA Cryptosuites v1.0 Achieving Data Integrity using EdDSA with Edwards curves](https://w3c.github.io/vc-di-eddsa/), W3C Candidate Recommendation Snapshot. *Caveat 1*
* [BBS Cryptosuite v2023 Securing Verifiable Credentials with Selective Disclosure using BBS Signatures](https://w3c.github.io/vc-di-bbs/)
* [Securing Verifiable Credentials using JOSE and COSE W3C Working Draft](https://w3c.github.io/vc-jose-cose/)

*Caveat 1*: I'm and editor on these specifications.

Hyperledger AnonCreds:

* [AnonCreds project page/overview](https://wiki.hyperledger.org/display/anoncreds)
* [AnonCreds Specification v1.0 Draft](https://hyperledger.github.io/anoncreds-spec/) Uses CL signatures, i.e., Jan Camenisch, Anna Lysyanskaya: A Signature Scheme with Efficient Protocols. SCN 2002: 268-289.
* Draft document [Anonymous credentials 2.0 version 0.2](https://wiki.hyperledger.org/download/attachments/6426712/Anoncreds2.1.pdf), Michael Lodder, Dmitry Khovratovich, 26 February 2019. Uses BBS+
* A critique of state of AnonCreds: [Being “Real” about Hyperledger Indy & Aries/Anoncreds ](https://identitywoman.net/being-real-about-hyperledger-indy-aries-anoncreds/), Kaliya Young · September 7, 2022
* Uses [Trust over IP Model](https://trustoverip.org/wp-content/toip-model/) of Issuer, Holder, Verifier

## Selective Disclosure

Go over selective disclosure in the three party model. Multiple statements (messages)

General approaches:

* Sign individual statements **Individual Signing**
* Hash (salted) individual statements arrange in a list and hash, or arrange in a tree hashing intermediate results **Merkel Tree**
* BBS like, i.e., the signature system works with multiple messages and directly works with selective disclosure **BBS**

Sizing of general approaches (signature, proof, M messages, D disclosed messages)

* **Individual Signing**: Signature -- M*signature size; Proof: D*signature size
* **Merkel Tree**: Signature -- 1 * signature size + overheads for salts (if used); Proof: 1 * signature size + worst case a hash value for every non-disclosed statement (M-D)
* **BBS**: Signature single relatively short signature independent of M; Proof: basic algorithm overhead + (M-D) scalars

Some Higher Level Selective Disclosure Protocols:

* [Selective Disclosure for JWTs (SD-JWT)](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-sd-jwt-structure) IETF Draft.
* [JSON Web Proof](https://www.ietf.org/archive/id/draft-ietf-jose-json-web-proof-01.html) IETF Draft, (supports BBS as well as other cryptographic approaches).
* ECDSA-SD and SD-primitives in [Data Integrity ECDSA Cryptosuites v1.0 Achieving Data Integrity using ECDSA with NIST-compliant curves](https://w3c.github.io/vc-di-ecdsa/).

## Unlinkable Proofs

Why? Tracking! Unique identifiers! Finger printing!

Threat models:


# Paper Summaries

## References

These are in reverse chronological order.

* "Revisiting BBS Signatures", Stefano Tessaro and Chenzhi Zhu. Preprint in PDF (under my references), end of 2022. Presented to DIF BBS WG. Has an extensive bibliography. The abstract is particularly useful as a history and summary. For example they say: "BBS signatures were implicitly proposed by Boneh, Boyen, and Shacham (CRYPTO ’04) as part of their group signature scheme, and explicitly cast as stand-alone signatures by Camenisch and Lysyanskaya (CRYPTO ’04)." This somewhat explains why the original paper is hard to reconcile with the draft, i.e., "implicitly proposed". https://eprint.iacr.org/2023/275

* Jan Camenisch, Manu Drijvers, and Anja Lehmann. Anonymous attestation using the strong Diffie-Hellman assumption revisited. In Michael Franz and Panos Papadimitratos, editors, Trust and Trustworthy Computing - 9th International Conference, TRUST 2016, Vienna, Austria, August 29-30, 2016, Proceedings, volume 9824 of Lecture Notes in Computer Science, pages 1–20. Springer, 2016. **Downloaded PDF in Zotero**. In section 4 I see procedures that look like (but didn't confirm) the procedures in the draft. **Need** to read more closely. Cited by draft. Section 4.4 and 4.5 cover the proof protocols. **Focus**

* Jan Camenisch, Aggelos Kiayias, and Moti Yung. On the portability of generalized Schnorr proofs. In Antoine Joux, editor, EUROCRYPT 2009, volume 5479 of LNCS, pages 425–442. Springer, Heidelberg, April 2009. *Notes*: This is referenced by the above paper to give the details on how to come up with the "poofs of knowledge of the signature". However this is very general and hence difficult to read. They point the readers to CS 1997 paper given below for the basics.

* Man Ho Au, Willy Susilo, and Yi Mu. Constant-size dynamic k-TAA. In Roberto De Prisco and Moti Yung, editors, SCN 06, volume 4116 of LNCS, pages 111–125. Springer, Heidelberg, September 2006. "k-times anonymous authentication (k-TAA) schemes allow members of a group to be authenticated anonymously by application providers for a bounded number of times. Dynamic k-TAA allows application providers to independently grant or revoke users from their own access group so as to provide better control over their clients" They coin the term BBS+ here and prove some security properties along the way to their scheme. They cite the paper below for the idea. In section 4 they "construct" their scheme. Along the way in section 4.2 they define the BBS+ scheme which includes the signature scheme for multiple messages and a zero knowledge proof of knowledge of the signature. However the proof of knowledge takes place in the G_T group where things are slow.

* J. Camenisch and A. Lysyanskaya. Signature Schemes and Anonymous Credentials from Bilinear Maps. In CRYPTO, pages 56–72, 2004. I've downloaded a 2005 version.

* Dan Boneh, Xavier Boyen, and Hovav Shacham. Short group signatures. In Matthew Franklin, editor,
CRYPTO 2004, volume 3152 of LNCS, pages 41–55. Springer, Heidelberg, August 2004.

* Jan Camenisch and Markus Stadler. Efficient group signature schemes for large groups. Lecture Notes in Computer Science, 1294:410–424, 1997. *Notes*: The proofs of knowledge stuff is contained in section 3 and section 3.3 in particular covers "signature of knowledge of discrete logs".

* Torben Pryds Pedersen. Non-interactive and information-theoretic secure verifiable secret sharing. In Joan Feigenbaum, editor, Advances in Cryptology – CRYPTO ’91, volume 576 of Lecture Notes in Computer Science, pages 129–140. Springer Verlag, 1992. **Fundamental** commitment scheme widely cited.

* Amos Fiat and Adi Shamir. How to prove yourself: Practical solution to identification and signature problems. In Andrew M. Odlyzko, editor, Advances in Cryptology — CRYPTO ’86, volume 263 of Lecture Notes in Computer Science, pages 186–194. Springer Verlag, 1987. **Fundamental** widely cited. PDF in Zotero.

Note for general, modern, rigorous, but readable cryptograpic background I'm reviewing [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/).

## BBS 2004 Notes

From the introduction:

> Group signatures, introduced by Chaum and van Heyst, provide **anonymity for signers**. Any member of the group can sign messages, but the resulting signature keeps the identity of the signer secret. In some systems there is a third party that can trace the signature, or undo its anonymity, using a special trapdoor. Some systems support revocation where group membership can be selectively disabled without affecting the signing ability of unrevoked members.

Properties of group signatures from paper:

* correctness, which ensures that honestly-generated signatures verify and trace correctly;
* full-anonymity, which ensures that signatures do not reveal their signer’s identity; and
* full-traceability, which ensures that all signatures, even those created by the collusion of multiple users and the group manager, trace to a member of the forging coalition.

In section 6 they define their "Short Group Signatures from SDH" which consists of the following processes:

* Key generation which takes as parameter $n$ the number of members of the group. This generates the group public key, private keys for each group member, and a private key for the group manager (the party that is allowed to trace signatures)
* Sign a message with a group members private key
* Verify a message and signature against the group public key
* *Open*: This algorithm is used for tracing a signature to a signer and requires the group managers secret key along with the message and signature

They prove the following properties about their group signature scheme:

* Theorem 2. The SDH group signature scheme is correct.
* Theorem 3. If Linear encryption is (t′,′)-semantically secure on G1 then the SDH group signature scheme is (t, qH,)-CPA-fully-anonymous, where  = ′ and t = t′ − qHO(1).Here qH is the number of hash function queries made by the adversary and n is the number of members of the group.
* Theorem 4. If SDH is (q, t′,′)-hard on (G1,G2), then the SDH group signature scheme is (t, qH,qS,n,)-fully-traceable, where n = q − 1,  =4n√2′qH + n/p, and t = Θ(1) · t′.HereqH is the number of hash function queries made by the adversary, qS is the number of signing queries made by the adversary, and n is the number of members of the group.


"The security of our scheme is based on the Strong Diffie-Hellman (SDH) assumption in groups with a bilinear map."

"Our system is based on a new Zero-Knowledge Proof of Knowledge (ZKPK) of the solution to an SDH problem. We convert this ZKPK to a group signature via the Fiat-Shamir heuristic and prove security in the *random oracle model*."

Key definitions in paper: "Bilinear Group", "q-Strong Diffie-Hellman Problem"

**TODO** summarize linear DH assumption and zero knowledge protocol 1.

Key results: "Theorem 1. Protocol 1 is an honest-verifier zero-knowledge proof of knowledge of an SDH pair under the Decision Linear assumption."




## Camenisch and Lysyanskaya 2004 Notes

"provably secure in the plain model"

"We then show how our scheme can be used to construct efficient anonymous credential systems as well as group signature and identity escrow schemes."

"we provide efficient protocols that allow one to prove in zero-knowledge the knowledge of a signature on a committed (or encrypted) message and to obtain a signature on a committed message."

Note the expression $1^k$ is used to formalize things. The integer $k$ is the security parameter, i.e., the number of bits of security. This stack exchange [post: Why does key generation take an input 1^k](https://crypto.stackexchange.com/questions/8174/why-does-key-generation-take-an-input-1k-and-how-do-i-represent-it-in-practi)

They gives a formal definition of a "signature scheme secure against adaptive chosen-message attack."

### Signature Scheme

From the paper:

Probabilistic polynomial-time algorithms $(G(·), Sign(·)(·), Verify(·)(·, ·))$, where $G$ is the key generation algorithm, $Sign$ is the signature algorithm, and $Verify$ the verification algorithm, constitute a digital signature scheme for a family (indexed by the public key $pk$ ) of message spaces M(·) if:

**Correctness**. If a message $m$ is in the message space for a given public key $pk$ , and $sk$ is the corresponding secret key, then the output of $Sign_{sk}(m)$ will always be accepted by the verification algorithm $Verify_{pk}$.

**Security**. Even if an adversary has oracle access to the signing algorithm which provides signatures on messages of the adversary’s choice, the adversary cannot create a valid signature on a message not explicitly queried.

With formal definitions of *correctness* and *security* given in the paper. Note that the *security* formalism requires turing machines and oracles.

### Math Preliminaries

They let $q$ be a prime number of roughly the order of $2^k$. They have two different groups of order $q$. $\mathbb{G}$, $G$, they have a bilinear pairing $e: \mathbb{G} \times \mathbb{G}\rightarrow G$.

### LRSW Assumptions

**LRSW Assumption**. Suppose that $G = 〈g〉$ is a group chosen by the setup algorithm Setup. Let X, Y ∈ G, $X = g^x$, $Y = g^y$. Let OX,Y (·) be an oracle that, on input a value $m ∈ Z_q$, outputs a triple $A = (a, a^y, a^{x+mxy})$ for a randomly chosen a.

Then (informally) it will be very unlikely that you can find an $m^\prime$ which will match the triple above $m \ne m^\prime$

I found their definition a bit hard to grok in detail. I found [A Classification of Computational Assumptions in the Algebraic Group Model](https://eprint.iacr.org/2020/859.pdf) section 4 clearer on this. They have the LRSW assumption as one of the assumptions they classify.

### Pedersen Commitment

Recall the Pedersen commitment scheme [Ped92]: given a group $G$ of prime order q with generators $g$ and $h$, a commitment to $x \in \mathbb{Z}_q$ is formed by choosing a random $r \gets \mathbb{Z}_q$ and setting the commitment $C = g^xh^r$. This commitment scheme is information-theoretically hiding, and is binding under the discrete logarithm assumption, which is implied by the LRSW assumption.

*Note*: This commitment is "opened" by revealing $x$ and $r$.

## Camenisch, Drijvers, and Lehmann 2016

This paper almost has all the details for the computations. However it leaves some of the proof generation a bit undefined. In section 4.4 they say:

"Indeed, the computational complexities of the proof protocol can be easily derived from this notation: for each term $y = g^ah^b$, the prover and the verifier have to perform an equivalent computation, and to transmit one group element and one response value for each exponent."

For this they point to the CYK09

### Formulas

**Key Generation**: $(h_0, \dots, h_L) \xleftarrow[]{\$}\mathbb{G}_1^{L+1}$, $x \xleftarrow[]{\$} \mathbb{Z}_p^*$, $w \gets g_2^x$, and set $sk = x$ and $pk = (w, h_0,\dots, h_L)$

**Signature**: On input message $(m_1, \dots, m_L) \in \mathbb{Z}_p^L$ and secret key $x$, pick $e, s \xleftarrow[]{\$} \mathbb{Z}_p$ and compute $A \gets (g_1 h_0^s \prod_{i=1}^L h_i^{m_i})^{\frac{1}{e + x}}$. Output signature $\sigma \gets (A, e, s)$.

**Verification**: On input a pulic key $(w, h_0,\dots, h_L) \in \mathbb{G}_2 \times \mathbb{G}_1^{L+1}$, message $(m_1, \dots, m_L) \in \mathbb{Z}_p^L$, and  purported signature $(A, e, s) \in \mathbb{G} \times \mathbb{Z}_p^2$, check $e(A, w g_2^e) =e(g_1 h_0^s \prod_{i=1}^L h_i^{m_i}, g_2)$

**Lemma 1**. The BBS+ signature scheme is existentially unforgeable against adaptive chosen message attacks under the JOC version of the qSDH assumption, in particular in pairing groups where no efficient isomorphism between $\mathbb{G}_2$ and $\mathbb{G}_1$ exists.

**Proof of knowledge of a BBS+ signature**: Prover has signature $\sigma \gets (A, e, s)$ with $A = (g_1 h_0^s \prod_{i=1}^L h_i^{m_i})^{\frac{1}{e + x}}$. Prover selectively discloses messages $m_i$ with $i \in D$. Randomization: $r_1 \xleftarrow[]{\$} \mathbb{Z}_p^*$, set $A' =A^{r_1}$, and set $r_3 \gets \frac{1}{r_1}$. Set $\bar{A} \gets A^{\prime - e}\cdot b^{r_1}$. Where $b = g_1 h_0^s \prod_{i=1}^L h_i^{m_i} = A^{e + x}$> Note that $\bar{A} = A^{\prime x}$. *STOPPED HERE*

## AnonCreds

References:

* [Anonymous Credential Part 1: Brief Overview and History](https://medium.com/finema/anonymous-credential-part-1-brief-overview-and-history-c6679034c914), Nuttawut Kongsuwan, Oct 1, 2020.
* [Anonymous Credential Part 2: Selective Disclosure and CL Signature](https://medium.com/finema/anonymous-credential-part-2-selective-disclosure-and-cl-signature-b904a93a1565), Rachata Tosirisuk, Feb 3, 2021.
* [Anonymous Credential Part 3: BBS+ Signature](https://medium.com/finema/anonymous-credential-part-3-bbs-signature-26797721ca74), Rachata Tosirisuk, Oct 27, 2020
* [Hyperledger AnonCreds (home)](https://wiki.hyperledger.org/display/anoncreds)
* [AnonCreds Specification](https://hyperledger.github.io/anoncreds-spec), Readable.
* [GitHub repo for AnonCreds specification](https://github.com/hyperledger/anoncreds-spec)

Notes: CL Signatures are based on RSA like mechanisms. They provide for selective disclosure and unlinkability like BBS but are significantly larger. AnonCreds 2.0 uses BBS while AnonCreds 1.0 uses CL.

> The AnonCreds (Anonymous Credentials) specification is based on the open source verifiable credential implementation of AnonCreds that has been in use since 2017, initially as part of the Hyperledger Indy open source project and now in the Hyperledger AnonCreds project.

> The use of Zero Knowledge Proofs (ZKPs) in the verifiable presentation process to enhance the privacy protections available to the holder in presenting data to verifiers, including:

* Blinding issuer signatures to prevent correlation based on those signatures.
* The use of unrevealed identifiers for holder binding to prevent correlation based on such identifiers.
* The use of predicate proofs to reduce the sharing of PII and potentially correlating data, especially dates (birth, credential issuance/expiry, etc.).
* A revocation scheme that proves a presentation is based on credentials that have not been revoked by the issuers without revealing correlatable revocation identifiers.

## Key Links/Sites

* [DIF: BBS Signature Draft](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#)
* [GitHub DIF BBS](https://github.com/decentralized-identity/bbs-signature) Uses markdown and tooling to produce draft. Has test fixtures/vectors.
* [The BBS Signature Scheme (IRTF draft)](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-02.html)
* [My public repo for JavaScript BBS implementation](https://github.com/Wind4Greg/grotto-bbs-signatures)
* [W3C: BBS+ Signatures 2020 Draft Community Group Report](https://w3c-ccg.github.io/vc-di-bbs/)
* [GitHub: BBS+ Signature Linked Data Proofs](https://github.com/w3c-ccg/ldp-bbs2020/)
* [Alternative Elliptic Curve Representations (draft)](https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23) This has come up in discussions on representations of keys in the BBS DIF working group.
* [Barreto-Lynn-Scott Elliptic Curve Key Representations for JOSE and COSE](https://www.ietf.org/archive/id/draft-ietf-cose-bls-key-representations-02.html)
* [GitHub: blst](https://github.com/supranational/blst) High performance, secure BLS12-381 implementation
* [Cryptol](https://cryptol.net/index.html) language and tool for specifying cryptographic algorithms. Used in evaluation of BLST and other implementations.
* [Verified Cryptographic Code for Everybody](https://galois.com/wp-content/uploads/2021/06/verified-cryptographic-code-for-everybody.pdf) Paper by company with tools and such for checking cryptography algorithms.