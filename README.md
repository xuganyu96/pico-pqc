# Pico-OQS
Benchmarking post-quantum cryptographic primitives on Raspberry Pi Pico 2 W.

## liboqs
This project depends on `liboqs`. Use the environment variable `LIBOQS_PATH` to point to the directory of build artifacts. We specifically need `$LIBOQS_PATH/include` for the headers and `$LIBOQS_PATH/lib/liboqs.a` to link against when compiling.