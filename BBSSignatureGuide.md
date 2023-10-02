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
   2. Three party model: Issuer, Holder, Verifier
   3. Issuer Efficient Selective Disclosure (short issuer signature, holder proof grows linearly with number of messages not disclosed) -- quick comparison to other selective disclosure approaches
   4. Unlinkable signatures (holder supplies "signature proof of knowledge" to verifier instead of original signature from issuer)
   5. Tracking/Linking Threat Model: Verifier-Verifier collusion, Issuer-Verifier collusion
   6. Other signature schemes that provide unlinkability (quick review)
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
   1. ZKP via Sigma Protocols for general linear relations
      1. CKY2009 *On the portability of generalized Schnorr proofs*
      2. CS1997 *Efficient group signature schemes for large groups*
   2. Fiat-Shamir heuristic: FS1987 *How to prove yourself: Practical solution to identification and signature problems*
   3. Pedersen Commitments: Ped1992 *Non-interactive and information-theoretic secure verifiable secret sharing*

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

### LRSW Assumptioins

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