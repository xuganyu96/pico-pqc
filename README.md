# Pico-OQS
Benchmarking post-quantum cryptographic primitives on Raspberry Pi Pico 2 W.

## liboqs
This project depends on `liboqs`. Use the environment variable `LIBOQS_PATH` to point to the directory of build artifacts. We specifically need `$LIBOQS_PATH/include` for the headers and `$LIBOQS_PATH/lib/liboqs.a` to link against when compiling.

## picotool
[picotool](https://github.com/raspberrypi/picotool) can be used to flash the Pico board without having to do the whole "press BOOTSEL then plug in the USB drive". Here is how I set it up:

- Clone the repository and buid the project `mkdir build && cd build && cmake .. && make`. this should produce a `picotool` binary.
- (OPTIONAL) do whatever is needed to make `picotool` discoverable by the shell (add to `$PATH`, symlink, etc)
- Configure the current firmware such that USB serial connection is enabled. In this project it means adding the line `pico_enable_stdio_usb(<target> 1)`. This firmware needs to be flashed onto the board.
- Use the command `picotool load -f <firmware.uf2>`, where `-f` will use the USB serial connection to force the board into BOOTSEL mode, and the firmware can be flashed
