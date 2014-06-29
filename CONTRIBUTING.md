All code must follow the OpenBSD style guide, and compile cleanly under maximal
warnings.

In addition:
   * headers must not include headers (plan 9 style)
   * macros are never allowed
   * no pointer arithmetic
   * all memory access must be checked
   * we target POSIX
   * we never expose structures: use accessor functions instead
   * C means C99
   * No #ifdef: instead provide two implementations of the same function
     and have the build scripts pick one.
   * All secrets must never leak to program counters or load addresses
   * (Exception: non AEAD cipher modes)
   * All cryptography must be strong
   * Assembler only permitted for crypto
