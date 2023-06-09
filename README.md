# sprav-vrac
SPRAV verifier remote attestation code

This is supplementary software to [SPRAV](https://github.com/mabarger/zephyr-sprav/tree/sprav), specifically to the prover remote attestation code (`prac`), which is part of SPRAV. `sprav-vrac` runs on the verifier, from where it will send an attestation request to the `prac` and will verify the signature in the attestation response. This is a proof-of-concept and is not intended for production environments.

# liboqs
Before compiling `liboqs` needs to be synced as follows:
```
git submodule init
git submodule update
```

# Compilation

```
mkdir build && cd build
cmake ..
make
```

# Usage
The application will connect to `SPRAV` running on another device via UART. If the device is connected to your machine simply run `sprav-vrac` from the repository root:
```
$ ./build/sprav-vrac
[~] attestation request sent to prover
    |- addr:  0x40380000
    |- size:  0x00002000
    |- nonce: 0xd42953d6
[~] waiting for attestation response
[~] received attestation response
[+] signature is valid
```

# Cryptography
The cryptographic material used is stored in `keys`. Note that the keys in there are only for testing purposes and should be replaced by the actual keys before use.
