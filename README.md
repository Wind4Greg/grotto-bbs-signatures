# JavaScript BBS Signatures

This repository contains an all JavaScript implementation of the emerging BBS+ digital 
signature standard being developed in conjunction with the 
[Decentralized Identity Foundation (DIF)](https://identity.foundation/) and the [Crypto Forum Research Group (CFRG) of the IRTF](https://datatracker.ietf.org/rg/cfrg/about/).

You can find the latest draft specification at [The BBS Signature Scheme (DIF)](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) this work then feeds into the IRTF draft which is available at [draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/).

Note that there are other draft implementations available notably in Rust, Typescript, etc... This is a *JavaScript only* implementation with a single dependency on the [noble-curves](https://github.com/paulmillr/noble-curves) project which has a single dependency on the [noble-hash](https://github.com/paulmillr/noble-hashes) project. This implementation can be used with Node.js or in the browser. We provide Node.js based example code and you can see our [BBS Signature Demo](https://www.grotto-networking.com/BBSDemo/) where we use this library in the browser to demonstrate interactively the properties of BBS signatures.

## BBS Signature Basics

BBS signatures are different from other common digital signatures schemes such as [EdDSA](https://en.wikipedia.org/wiki/EdDSA) or [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) in that it supports:

1. The signing of multiple messages at a time, rather than a single message.
2. A single short signature covering all the messages.
3. The ability to derive a secondary signature, called a *proof* in BBS terminology, that may choose not to disclose some of the messages in the original signature. This is called *selective disclosure*.
4. The digital *proofs* generated in the previous section are *unlinkable* to each other in the cryptographic sense, and cannot be used for tracking. Note that this does not apply to any information disclosed.

Both the original *signature* and any *proofs* generated are verified with the original issuers *public key*.  The contents of individual messages covered by a signature may not be changed, nor can new messages be added to a *proof* only messages can be withheld from a *proof* and still have the *proof* verify.

One prime example of the use of BBS signatures is in a three party *issuer*, *holder*, *verifier* model. For example suppose the issuer is the department of motor vehicles (DMV) and wants to issue the digital equivalent of a drivers license which contains an assortment of information. A fictitious set of information is shown below in JSON format for a **tree** living in northern California:

``` json
[   "FirstName: Sequoia",
    "LastName: Sempervirens",
    "Address: Jedediah Smith Redwoods State Park, California",
    "Date of Birth: 1200/03/21",
    "Height: 296 feet",
    "Eyes: None",
    "Hair: Brown bark, green needles",
    "Picture: Encoded photo",
    "License Class: None, Trees can't drive" ]
```

The DMV would use its secret key to produce a signature on this list of *messages*. It would then return to the *holder*, the aforementioned tree in out case, a bundle of information containing the signature, i.e., something like:

```json
{
  "publicKey": "b79263bb3177955a347b8d4dd25f8dc08990687b61af88014f78f17dd24f4b13154785fd797a540e0f7e87abcbfca5b3143c9f6db5b117b2c28f8f1f449ef8327c8c15952ed118d098966f434c67cc15671de7d95d860393c0362b55608fe457",
  "header": "11223344556677889900aabbccddeeff",
  "messages": [
    "FirstName: Sequoia             ",
    "LastName: Sempervirens",
    "Address: Jedediah Smith Redwoods State Park ",
    "Date of Birth: 1200/03/21",
    "Height: 296 feet",
    "Eyes: None",
    "Hair: Brown bark, green needles",
    "Picture: Encoded photo",
    "License Class: None, Trees can't drive"
  ],
  "signature": "b712c3c1c9f134bdea96134845a8c4d7afe3335673241738d39d060a2d87a77d93110cb4022a2a8fd7ff24c3c1715ebe48f2e6bf1ff31f7ddd74a84136b01a8c2a595d2d6132b85f264cbf874b3bf2581fbdc263d65164c475e6482b27cc56d3c2413dc69958daa4dee264a8f0cfc6cd"
}
```

Note that this "document" contains a lot of potentially sensitive information. Hence should be sent securely from the *issuer* to the *holder* .

Now suppose that the tree needs to prove its age, e.g., in order to gain entrance to a club or bar, but doesn't want to divulge any extra information besides the minimum necessary, i.e., it just wants to show the following to the bouncer at the door in a verifiable manner:

``` json
[    "Date of Birth: 1200/03/21",
    "Picture: Encoded photo" ]
```

It then uses the BBS proof generation algorithm to generate proof information such as:

```json
{
  "pk": "b79263bb3177955a347b8d4dd25f8dc08990687b61af88014f78f17dd24f4b13154785fd797a540e0f7e87abcbfca5b3143c9f6db5b117b2c28f8f1f449ef8327c8c15952ed118d098966f434c67cc15671de7d95d860393c0362b55608fe457",
  "header": "11223344556677889900aabbccddeeff",
  "ph": "",
  "disclosedIndexes": [
    3,
    7
  ],
  "disclosedMsgs": [
    "Date of Birth: 1200/03/21",
    "Picture: Encoded photo"
  ],
  "proof": "80bbc63a921617243b2e7ef845c2e62aaae2b0b8030ad851f03d3880606c1473ff25ce3d50e9a76475cbf9d4920c13edb1ad86a066aa9b9a18518e7a649d89681ef145a104548cee1e732ef2958949f86e7f835abbbb14d6b823b9275dc8fd28a080457971a5412fd7134b42ac5e1dab73f3a8079e31ef26787dcf7761099ff2c4baafcf8e5907fb8f7df53acd53b6d83af1943205cb2d94461b1532a118186a38580080bb25b9d12867ae51ab6ff10f053d267fb152b9bebe58b12e7183f0b95ddce2d417ec2871048e8bf1e78791a1497bf2e5b0820b3a96a1ce9264b80f6791e9da1efbabc28c68b747cbe8edd7e73b3cdd9bec8b222e0f7b454f777b198debe304929a797c854ea2f5086a54ac612ee9c61d761f9fa65574b0498615110124be606b153f15da8549e73ed359c045037480ff15a66453d2c8a2c4dc6c312d34389c0ef7864f691361918950060c3c3fb5aa53513e33c120b622fc8320e4d609444e578eac93e6b23a40cae8768ebf1e833d400234f999f3c88b94fa4025d2e4a64634ac0a5849165b0beda77a29ec34333512b2aca2c42af73f8590a0929b5fedc4d3a5666301fa1faafb58ad37ed5c349f7f8c9539cbeaebffdfc46addc578abc7df925dec9291375841721241271e64cdfa88bfe584811368cbddf5bffb5e6613d91afba66dc67c87dfb2fa017145ce24648b624a0588682e7bb92709531dcdc7bca0345b19ce535c90f2e3afc0"
}
```

The bouncer at the door, the *verifier*, verifies this against the DMV's public key, i.e., the two messages disclosed were part of the orginal signed information and have not been modified.

Now suppose this tree is very thirsty and visits another bar, given California's issue with drought the next bar states it will only serve trees from state or national parks. So the tree includes its address information as well as its photo and date of birth as follows:

``` json
[   "Address: Jedediah Smith Redwoods State Park",
    "Date of Birth: 1200/03/21",
    "Picture: Encoded photo" ]
```

It produces another BBS proof such as:

```json
{
  "pk": "b79263bb3177955a347b8d4dd25f8dc08990687b61af88014f78f17dd24f4b13154785fd797a540e0f7e87abcbfca5b3143c9f6db5b117b2c28f8f1f449ef8327c8c15952ed118d098966f434c67cc15671de7d95d860393c0362b55608fe457",
  "header": "11223344556677889900aabbccddeeff",
  "ph": "",
  "disclosedIndexes": [
    2,
    3,
    7
  ],
  "disclosedMsgs": [
    "Address: Jedediah Smith Redwoods State Park ",
    "Date of Birth: 1200/03/21",
    "Picture: Encoded photo"
  ],
  "totalMsgs": 9,
  "proof": "b735b3b81cd2f69f7e37444b6a99206748aa7b2e2dc77b01f07ffe5462d9c228fd967dcef936577dd06b7ef07908443d83a19b13959d3815e1ddd6b8690cfd7e0d9767f2d7cd5b97520a8e5b1ec44e8a098cf4e540904ed8ff6e44902382b7dbae76fdede3c319ee11cd6de5c1405fea46d954990ca87a9755e045b9d8a82e6686edbb6a61ad025d1e2d43ea833dc5d04e33a875ab53e609122e73ad50d23b8775ba8398b8904d493a3582276e5f8e102218bd71a0aeb4e635b552b9b7454a089d95e5548cbae4720b50af55ba45e40a05955e53fbe170f9131b4d9cf40b03dacc3203874b1eb9959e479203e27992773913d5a4c293f3e7db58bd9085e1072dd68d524caaf55541b7a6ae928a0b96374126816ce1ed79c108c2be8f0114898f3b7b2ae7194515bae3132edfb6928fd446ff97a142549df1451f1f73b5fa99c80cc8a2969f25bdb2f54be2dc8fb121912724a068c713f579d193d6a65f6d9acc8bfccec55c26fc5cb1541f6af9c8cb5869ca9a1608668bd3e474b0455ee56763e9f505455c38a32ba05e05b5d7fa1c405eee9d066bdabdf0331cb9dc0c08525c42b37172e6631a684382cffbad815ca96730c109e325b4b4c79927cd6c06a233a64274e53ce2fd769161e68dde6c6f8c0b7d0136f864502beb48b102a771f66b5d2838ec128f3dbd9a0e9b9f6233d075"
}
```

Which the bartender at the second bar can verify with the DMV's public key. By *unlinkable* we mean the cryptographic *proof* field in these two *proofs* are uncorrelated and can't be used to track the tree from bar to bar, however, the tree has disclosed its "date of birth" and "photo" to both bars which could be used for tracking purpose.

You may have noticed that the proofs in these two examples have different sizes. Currently BBS *signatures* have a size of 112 bytes, while BBS *proofs* have a size of $304 + U*32$ bytes where *U* is the number of undisclosed messages. We say currently since [new work](https://eprint.iacr.org/2023/275) may reduce these numbers a bit while preserving security properties.

## Library Usage

### Key Generation

### Message Encoding

### Generator Preparation

### Signing and Verifying

### Proof Generation and Verification


