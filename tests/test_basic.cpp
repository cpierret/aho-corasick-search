#include "aho_corasick.h"
#include <string>
#include <vector>
#include <cassert>

using namespace textsearch;

int match_cb(AhoCorasickSearch::any_t, int index, AhoCorasickSearch::any_t userdata) {
    auto results = std::any_cast<std::vector<int>*>(userdata);
    results->push_back(index);
    return 0;
}

int main() {
    AhoCorasickSearch ac;

    std::string pattern = "needle";
    ac.addPattern(pattern.begin(), pattern.end(), false, nullptr);
    ac.compile();

    std::string text = "haystack needle haystack needle";
    std::vector<int> matches;
    ac.search(text.begin(), text.end(), match_cb, &matches, 0, nullptr);

    assert(matches.size() == 2);
    assert(matches[0] == 9);
    assert(matches[1] == 25);
    return 0;
}
