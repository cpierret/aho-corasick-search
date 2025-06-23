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
