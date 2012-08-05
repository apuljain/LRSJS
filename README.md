LRSJS
=========
Dependencies
=========
Install node.js

Directory structure
===========
./
=====
*keygen.js		: Generates public private keys (1024 bits).
*LRSignature.js	: Signature components wrapper.
*LRSigner.js		: Prover object implementation.
*LRVerifier.js		: Verifier object implementation.

./library/
=====
*dsa.js			: Library to generate DSA keys (1024 bits).
*helpers.js		: helper library to provide utility functions.
*bigInt.js			: BigInt library for large integer arithmetic.
*sha1.js			: Standard sha1 hash library.
*sha256.js		: SHA-256 hash library.

./tests/
=====
*test.js			: Code to test the implementation of signer and verifier class.

Usage Instructions
==========
1. run "node keygen.js [no. of keys to generate]"
    This will generate public and private keys in private and public directories.

2. cd ./tests/

3. node test.js 
    This command load keys from public and private directories, creates signer and verifier
    objects; generates and verifies the signature generated by the signer.
    Note: Output on the terminal will be nothing if program terminates successfully else
    appropriate error is thrown on the screen.
 
Other Notes
======
*The implementation takes advantage of MPI to ensure platform portability. Signature is
 generated in MPI format.
*Public Private keys are generated as binary files (used JSON to serialize DSA keys objects
 into string).
