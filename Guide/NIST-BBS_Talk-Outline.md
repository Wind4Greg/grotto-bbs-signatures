---
title: BBS NIST Talk Outline
author: Dr. Greg M. Bernstein
date: 2023-10-05
---

# NIST BBS Talk Outline

Tentative Title: BBS+ Signatures: Applications, Standardizations, and a bit of Theory

Presenters: Dr. Greg M. Bernstein, Dr. Vasilis Kalos

Abstract: In this talk we present an overview of BBS+ signatures from an applications and standardization perspective. In addition we will review its cryptographic/ZKP underpinnings. Verifiable credentials are currently undergoing standardization as an electronic substitute/adjunct to many traditional types of credentials such as passports, educational transcripts, etc... BBS+ signatures can provide the key features of selective disclosure and unlinkability to verifiable credentials. However the road from academic papers to multi-vendor interoperable deployment requires working through multiple standards development organizations. We describe this process for BBS+ via our work at the IETF, DIF, and W3C.

1. Application Scenarios and Benefits  (Greg)
   1. Intro: Applications to Standards to Papers
      1. Applications Drives Standards which "shop for results" which can lead to more results or refinements
      2. BBS+ Draft Standard and Papers
   2. Verifiable Credentials (W3C) and AnonCreds (HyperLedger)
      1. Three party model: Issuer, Holder, Verifier
      2. VC and Cryptography: current specifications in progress
      3. BBS in Browser Demo
   3. Selective Disclosure
      1. What is it? Example
      2. Quick comparison to other high level selective disclosure approaches
      3. Size characteristics of general selective disclosure approaches
   4. Unlinkable Signatures
      1. Tracking/Linking Threat Model: Verifier-Verifier collusion, Issuer-Verifier collusion
      2. What is he problem? Example with BBS
      3. Not just a signature problem. Uniqueness of information and artifacts
      4. Other signature schemes that provide unlinkability (omit)
2. Standardization and a bit of Theory (Vasilis)
   1. Theoretical Basis for BBS+ signatures
   2. From theory to standards

Extra Ideas:

1. Quick History
   1. Security Models: Plain, Random Oracle, AGM...
   2. BBS2004 *Short group signatures*
   3. CL2004 *Signature Schemes and Anonymous Credentials from Bilinear Maps*
   4. ASM2006 *Constant-size dynamic k-TAA*
   5. CDL2016 *Anonymous attestation using the strong Diffie-Hellman assumption revisited*
   6. TZ2023 *Revisiting BBS Signatures*
2. Key Supplemental Techniques
   1. ZKP via Sigma Protocols for general linear relations (simplest to most general)
      1. [Schnorr Non-interactive Zero-Knowledge Proof (RFC8235)](https://www.rfc-editor.org/rfc/rfc8235.html), 2017. Provides full details.
      2. CS1997 *Efficient group signature schemes for large groups*
      3. CKY2009 *On the portability of generalized Schnorr proofs*
   2. Fiat-Shamir heuristic: FS1987 *How to prove yourself: Practical solution to identification and signature problems*
   3. Pedersen Commitments: Ped1992 *Non-interactive and information-theoretic secure verifiable secret sharing*

Cut from Greg:

2. Standardization Part I (Greg -- cut)
      1. Standards Development Organizations and Others. So many to choose from
      2. Goal interoperability: Proof multiple independent implementations
      3. How Open? Costs? Participant Pool (just vendors, just customers)
      4. History and Expertise, Process (frequency of meeting)
      5. DIF and IETF recent history Elliptic Curves, Pairings, Hash to Curve