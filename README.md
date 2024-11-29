# EmuFuzz

EmuFuzz is a structure-aware fuzzer for CPU emulators, specifically for the ARM32 ISA. It uses LibFuzzer as its core fuzzing engine and custom structure-aware mutations. 

# Setup
- Install unicorn-engine: https://github.com/unicorn-engine/unicorn (you will need to clone and build the repo)
- Install Capstone disassembler: https://www.capstone-engine.org/
- Install Keystone assembler: https://www.keystone-engine.org/
- Install LibFuzzer with clang: https://llvm.org/docs/LibFuzzer.html 

# Compiling EmuFuzz
- Navigate to `unicorn/tests/fuzz` on your device
- Put the `mutator_arm32.c` file and `arm_seeds` folder there
- Run:

```bash
clang -fsanitize=address,fuzzer mutator_arm32.c ../../build/libunicorn.a -I../../include -o mutator_arm32 -lcapstone -lkeystone -DCUSTOM_MUTATOR
```

- Ensure clang, capstone and keystone are installed in default locations on your computer. Else you will have to modify the above command depending on the installation location.

# Running EmuFuzz
- Create a folder `arm_corpus/` in `unicorn/tests/fuzz` to store the new corpus files from the fuzzing run
- On MacOS you can simply run the fuzzer with seeds using the following command:

```bash
./mutator_arm32 arm_corpus/ arm_seeds/
```

- On Ubuntu, run the fuzzer like this:

```bash
./mutator_arm32 arm_corpus/ arm_seeds/ -detect_leaks=0
```

- This fuzzer has not been tested on Windows-based systems. 