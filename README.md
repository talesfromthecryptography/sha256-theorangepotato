# SHA-256
Written by Austin Bohannon and Dr. Andrew Moshier

This implements [SHA-256 hashing](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) in ANSI C. The code compiles without any warnings nor errors and it has no memory leaks according to [valgrind](http://valgrind.org/).

## Build
While this code has no runtime dependencies, its development dependencies are: git, gcc, and the C standard libraries. Make sure you have these installed on your system before following the rest of the instructions. Additionally, all instructions in this README are given for Unix-like systems (Linux, MacOS, etc.).

To build, first check out this repository with:

```bash
git clone https://github.com/talesfromthecryptography/sha256-theorangepotato.git
cd sha256-theorangepotato/
```

Then, merely run:

```bash
gcc -ansi test_sha256.c sha256.c sha256.h -o test_sha256
```

## Run
Once built, there should be an executable in the same folder. If built with the above command, it will look like:

```bash
./test_sha256
```

This will run all of the tests in `test_sha256.c`, and the output should look like this:
```
TEST PASSED
TEST PASSED
TEST PASSED
TEST PASSED
```

If a test fails, it will tell you the hash it calculated, and what the hash should have been according to [GNU coreutils](https://www.gnu.org/software/coreutils/coreutils.html).

## License
[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)