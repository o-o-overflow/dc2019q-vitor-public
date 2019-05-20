# Vitor

Matryoshka-style Android reversing chall.

The app had several (encrypted) stages. Each stage would decrypt the next stage and execute it. The stages had all different nature:
- P0: main app
- P1: DEX code
- P2: .so code
- P3: shellcode
- P4: ROP
- P5: JavaScript

More info:
- The JavaScript payload would then modify a static variable in P0, marking the flag as valid.
- It was possible to determine the decryption key of each stage because 1) the key space was 31 bits, 2) it was clear what the next stage would look like. P1 and P2 required bruteforcing (and checking for magic bytes of DEX and ELF). The remaining ones didn't (e.g., a comment in the app made clear that the shellcode started with a nop sled, P5 needed to start with "<html>", etc.)
- All the encryption keys are derived from the input flag. The right encryption keys would give enough constraints to recover the flag.


# Build

- Check `build.sh` for building the various stages and assemble the final Vitor app.
- You need to run this script within a python virtual environment (`pip install -r requirements.txt`).
- You need to have installed Android Studio / SDK / NDK / etc.
