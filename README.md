# JavaScript BBS Signatures

This repository contains an all JavaScript implementation of the emerging BBS+ digital 
signature standard being developed in conjunction with the 
[Decentralized Identity Foundation (DIF)](https://identity.foundation/) and the [Crypto Forum Research Group (CFRG) of the IRTF](https://datatracker.ietf.org/rg/cfrg/about/).

You can find the latest draft specification at [The BBS Signature Scheme (DIF)](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) this work then feeds into the IRTF draft which is available at [draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/).

Note that there are other draft implementations available notably in Rust, Typescript, etc... This is a *JavaScript only* implementation with a single dependency on the [noble-curves](https://github.com/paulmillr/noble-curves) project which has a single dependency on the [noble-hash](https://github.com/paulmillr/noble-hashes) project. This implementation can be used with Node.js or in the browser. We provide Node.js based example code and you can see our [BBS Signature Demo](https://www.grotto-networking.com/BBSDemo/) where we use this library in the browser to demonstrate interactively the properties of BBS signatures.
