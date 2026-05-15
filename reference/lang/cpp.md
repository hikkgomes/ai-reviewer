# C++ Review Module

Activate for `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.h`, and `.c`.

## Highest-Impact Checks

- Dangling pointers, references to temporaries, iterator invalidation.
- Manual `new`/`delete` where RAII or smart pointers should own lifetime.
- Double free, use-after-free, missing virtual destructors.
- Buffer overflow, unchecked bounds, unsafe C string functions.
- Integer overflow and signed/unsigned comparisons.
- Exception safety and partial mutation.

## AI-Specific Failures

- C-style memory management copied into modern C++ code.
- Missing ownership documentation around raw pointers.
- Header/source mismatch and ODR hazards.

## Common False Positives

- Non-owning raw pointers where local conventions clearly use them as views.
- Low-level code that intentionally avoids exceptions or heap allocation.
