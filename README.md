# Aho-Corasick Search

This library implements the [Aho–Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) algorithm for multi-pattern text searching. It aims to provide a compact and fast search engine using a sparse NFA implementation written in modern C++.

The code is released under the terms of the **GNU General Public License version 2 (GPLv2)**. See `LICENSE` for the complete text.

## Building

All sources are located under the `src/` directory. To build your own program that links against the library you need a C++17-capable compiler. The example below compiles `examples/example.cpp` together with the library sources:

```sh
g++ -std=c++17 -O2 -Isrc examples/example.cpp src/aho_corasick.cc -o example
```

The project also includes a cross‑platform [CMake](https://cmake.org/) build
system. It can be used to build the library and run the tests:

```sh
mkdir build && cd build
cmake .. -DENABLE_ASAN=ON -DBUILD_TESTS=ON
cmake --build .
ctest
```

To collect unit-test coverage with GCC or Clang, enable coverage
instrumentation and build the `coverage` target:

```sh
mkdir build-coverage && cd build-coverage
cmake .. -DBUILD_TESTS=ON -DENABLE_COVERAGE=ON
cmake --build . --target coverage
```

The generated `gcov` reports are written to `build-coverage/coverage/`.

To generate API documentation, install Doxygen and build the `docs` target:

```sh
cmake -S . -B build -DBUILD_DOCS=ON
cmake --build build --target docs
```

The generated HTML documentation is written to `docs/api/html/`.

## Public API

Include `aho_corasick.h` and use the `textsearch::AhoCorasickSearch` class.

Typical lifecycle:

1. Construct `AhoCorasickSearch`, optionally selecting a case mode.
2. Add all patterns with `addPattern()`.
3. Call `compile()`.
4. Call `search()` with a callback that receives each match.

Case modes:

- `BNFA_CASE`: case-sensitive matching.
- `BNFA_NOCASE`: case-insensitive matching for all patterns.
- `BNFA_PER_PAT_CASE`: each pattern decides case handling through the
  `nocase` argument passed to `addPattern()`.

The match callback receives the pattern userdata, the zero-based match start
index in the current search buffer, and the search userdata. Return a positive
value from the callback to stop searching early; return `0` to keep scanning.
Use callback side effects as the authoritative match-reporting mechanism.

`search()` accepts random-access iterators over `char` or `unsigned char`
compatible data. For single-buffer searches, pass `nullptr` for
`current_state`. For streaming searches, keep a `bnfa_state_index_t` initialized
to `0` and pass its address to each call.

## Usage example

```cpp
#include "aho_corasick.h"
#include <iostream>
#include <string>

using namespace textsearch;

int print_match(AhoCorasickSearch::any_t, int index, AhoCorasickSearch::any_t) {
    std::cout << "matched pattern " << index << std::endl;
    return 0;
}

int main() {
    AhoCorasickSearch ac;

    const std::string pattern = "needle";
    ac.addPattern(pattern.begin(), pattern.end(), false, nullptr);
    ac.compile();

    const std::string text = "haystack needle haystack";
    ac.search(text.begin(), text.end(), print_match, nullptr, 0, nullptr);
}
```

See the source files under `src/` for additional details and advanced usage.

## Streaming searches

For searches split across multiple buffers, pass the same non-null
`bnfa_state_index_t` state pointer to each `search()` call. A null state pointer
is supported for single-buffer searches.

In `BNFA_PER_PAT_CASE` mode, case-sensitive patterns that start in a previous
buffer and end in the current buffer are not reported because the API only
carries automaton state across calls, not the previous bytes required for exact
case verification. Use `BNFA_CASE`, `BNFA_NOCASE`, or per-pattern `nocase=true`
when cross-buffer matches are required.

## Visual Studio Code

This repository includes tasks for building and debugging the example
program. Run `Ctrl+Shift+B` to compile it or start the **Debug Example**
configuration to launch it under the debugger. A similar **Debug test_basic**
configuration and `build test_basic` task are provided for debugging the unit
test.

## Contributing

See `CONTRIBUTING.md` for build, test, documentation, style, and licensing
guidelines.
