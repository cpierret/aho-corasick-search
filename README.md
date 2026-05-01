# Aho-Corasick Search

This library implements the [Aho–Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) algorithm for multi-pattern text searching. It aims to provide a compact and fast search engine using a sparse NFA implementation written in modern C++.

The code is released under the terms of the **GNU General Public License version 2 (GPLv2)**. See `LICENSE` for the complete text.

## Building

All sources are located under the `src/` directory. To build your own program that links against the library you need a C++17-capable compiler. The example below compiles `examples/example.cpp` together with the library sources:

```sh
g++ -std=c++17 -O2 examples/example.cpp src/aho_corasick.cc -o example
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

## Python extension

The project can also build a native CPython extension with
[nanobind](https://nanobind.readthedocs.io/). This is intended for benchmark
integration where Python callback overhead would hide the C++ search cost.

Install nanobind into the Python environment used by CMake, then enable the
extension target:

```sh
python3 -m pip install nanobind
cmake -S . -B build-python -DBUILD_PYTHON_EXTENSION=ON -DBUILD_TESTS=ON
cmake --build build-python
ctest --test-dir build-python --output-on-failure
```

The extension module is written to the CMake build directory. For ad hoc use:

```sh
PYTHONPATH=build-python python3 - <<'PY'
import aho_corasick_search_ext

ac = aho_corasick_search_ext.AhoCorasick(["needle", "hay"])
print(ac.find_matches_as_indexes("haystack needle"))
print(ac.count_matches("haystack needle"))
PY
```

The Python API reports byte offsets. This is the fastest path and matches the
ASCII benchmark data used by `ahocorasick_rs`.

For native search profiling, enable instrumentation counters in a profiling
build:

```sh
cmake -S . -B build-python-stats \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_PYTHON_EXTENSION=ON \
  -DENABLE_SEARCH_STATS=ON
cmake --build build-python-stats
```

When built with `ENABLE_SEARCH_STATS=ON`, the Python `AhoCorasick` object also
provides `reset_search_stats()` and `get_search_stats()` for inspecting sparse
NFA transition behavior.

## Usage example

```cpp
#include "src/aho_corasick.h"
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
