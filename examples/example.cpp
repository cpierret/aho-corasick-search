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
