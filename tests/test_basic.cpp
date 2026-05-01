#include "aho_corasick.h"
#include <algorithm>
#include <any>
#include <cassert>
#include <string>
#include <utility>
#include <vector>

using textsearch::AhoCorasickSearch;

namespace {

using IdentifiedMatch = std::pair<int, int>;

int collect_match(AhoCorasickSearch::any_t, int index, AhoCorasickSearch::any_t userdata) {
    auto results = std::any_cast<std::vector<int>*>(userdata);
    results->push_back(index);
    return 0;
}

int collect_identified_match(AhoCorasickSearch::any_t pattern_data, int index, AhoCorasickSearch::any_t userdata) {
    auto results = std::any_cast<std::vector<IdentifiedMatch>*>(userdata);
    results->push_back({std::any_cast<int>(pattern_data), index});
    return 0;
}

int count_match(AhoCorasickSearch::any_t, int, AhoCorasickSearch::any_t userdata) {
    auto count = std::any_cast<int*>(userdata);
    ++(*count);
    return 0;
}

int stop_after_first_match(AhoCorasickSearch::any_t, int index, AhoCorasickSearch::any_t userdata) {
    auto results = std::any_cast<std::vector<int>*>(userdata);
    results->push_back(index);
    return 1;
}

bool has_match(const std::vector<IdentifiedMatch>& matches, const IdentifiedMatch& expected) {
    return std::find(matches.begin(), matches.end(), expected) != matches.end();
}

void add_pattern(
    AhoCorasickSearch& ac,
    const std::string& pattern,
    bool nocase = false,
    AhoCorasickSearch::any_t userdata = nullptr) {
    assert(ac.addPattern(pattern.begin(), pattern.end(), nocase, userdata) == 0);
}

} // namespace

int main() {
    AhoCorasickSearch ac;

    const std::string pattern = "needle";
    add_pattern(ac, pattern);
    assert(ac.compile() == 0);

    const std::string text = "haystack needle haystack";
    std::vector<int> matches;
    AhoCorasickSearch::bnfa_state_index_t state = 0;
    ac.search(text.begin(), text.end(), collect_match, &matches, 0, &state);

    assert(matches.size() == 1);
    assert(matches[0] == 9);

    matches.clear();
    ac.search(text.begin(), text.end(), collect_match, &matches, 0, nullptr);
    assert(matches.size() == 1);
    assert(matches[0] == 9);

    AhoCorasickSearch hello_search;
    const std::string hello = "hello";
    add_pattern(hello_search, hello);
    assert(hello_search.compile() == 0);

    const std::string sentence = "say hello to the world";
    int count = 0;
    state = 0;
    hello_search.search(sentence.begin(), sentence.end(), count_match, &count, 0, &state);
    assert(count == 1);

    AhoCorasickSearch no_case_search(AhoCorasickSearch::bnfa_case::BNFA_NOCASE);
    add_pattern(no_case_search, "Needle");
    assert(no_case_search.compile() == 0);

    const std::string mixed_case_text = "xx nEeDlE";
    matches.clear();
    state = 0;
    no_case_search.search(mixed_case_text.begin(), mixed_case_text.end(), collect_match, &matches, 0, &state);
    assert(matches.size() == 1);
    assert(matches[0] == 3);

    AhoCorasickSearch per_pattern_case_search(AhoCorasickSearch::bnfa_case::BNFA_PER_PAT_CASE);
    add_pattern(per_pattern_case_search, "Needle");
    assert(per_pattern_case_search.compile() == 0);

    const std::string per_pattern_text = "needle Needle";
    matches.clear();
    state = 0;
    per_pattern_case_search.search(per_pattern_text.begin(), per_pattern_text.end(), collect_match, &matches, 0, &state);
    assert(matches.size() == 1);
    assert(matches[0] == 7);

    AhoCorasickSearch sparse_search;
    for (char suffix = 'a'; suffix <= 'g'; ++suffix) {
        std::string sparse_pattern = "p";
        sparse_pattern.push_back(suffix);
        add_pattern(sparse_search, sparse_pattern);
    }
    assert(sparse_search.compile() == 0);

    const std::string sparse_text = "px pg";
    matches.clear();
    state = 0;
    sparse_search.search(sparse_text.begin(), sparse_text.end(), collect_match, &matches, 0, &state);
    assert(matches.size() == 1);
    assert(matches[0] == 3);

    AhoCorasickSearch streaming_search;
    add_pattern(streaming_search, "needle");
    assert(streaming_search.compile() == 0);

    const std::string first_chunk = "xx nee";
    const std::string second_chunk = "dle yy";
    count = 0;
    state = 0;
    streaming_search.search(first_chunk.begin(), first_chunk.end(), count_match, &count, 0, &state);
    streaming_search.search(second_chunk.begin(), second_chunk.end(), count_match, &count, 0, &state);
    assert(count == 1);

    AhoCorasickSearch optimized_search;
    optimized_search.setOptimizeFailureStates(true);
    add_pattern(optimized_search, "he");
    add_pattern(optimized_search, "hers");
    assert(optimized_search.compile() == 0);

    const std::string optimized_text = "hers";
    count = 0;
    state = 0;
    optimized_search.search(optimized_text.begin(), optimized_text.end(), count_match, &count, 0, &state);
    assert(count == 2);

    AhoCorasickSearch terminating_search;
    add_pattern(terminating_search, "a");
    assert(terminating_search.compile() == 0);

    const std::string repeated_text = "aaa";
    matches.clear();
    state = 0;
    assert(terminating_search.search(
               repeated_text.begin(), repeated_text.end(), stop_after_first_match, &matches, 0, &state) == 1);
    assert(matches.size() == 1);

    AhoCorasickSearch overlapping_search;
    add_pattern(overlapping_search, "he", false, 1);
    add_pattern(overlapping_search, "she", false, 2);
    add_pattern(overlapping_search, "hers", false, 3);
    assert(overlapping_search.compile() == 0);

    const std::string overlapping_text = "ushers";
    std::vector<IdentifiedMatch> identified_matches;
    state = 0;
    overlapping_search.search(
        overlapping_text.begin(),
        overlapping_text.end(),
        collect_identified_match,
        &identified_matches,
        0,
        &state);
    assert(identified_matches.size() == 3);
    assert(has_match(identified_matches, {1, 2}));
    assert(has_match(identified_matches, {2, 1}));
    assert(has_match(identified_matches, {3, 2}));

    return 0;
}
