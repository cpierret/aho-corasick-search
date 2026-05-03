#include "aho_corasick.h"
#include <algorithm>
#include <any>
#include <cstdlib>
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

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

void add_pattern(
    AhoCorasickSearch& ac,
    const std::string& pattern,
    bool nocase = false,
    AhoCorasickSearch::any_t userdata = nullptr) {
    require(ac.addPattern(pattern.begin(), pattern.end(), nocase, userdata) == 0);
}

} // namespace

int main() {
    AhoCorasickSearch ac;

    const std::string pattern = "needle";
    add_pattern(ac, pattern);
    require(ac.compile() == 0);

    const std::string text = "haystack needle haystack";
    std::vector<int> matches;
    AhoCorasickSearch::bnfa_state_index_t state = 0;
    ac.search(text.begin(), text.end(), collect_match, &matches, 0, &state);

    require(matches.size() == 1);
    require(matches[0] == 9);

    matches.clear();
    ac.search(text.begin(), text.end(), collect_match, &matches, 0, nullptr);
    require(matches.size() == 1);
    require(matches[0] == 9);

    AhoCorasickSearch hello_search;
    const std::string hello = "hello";
    add_pattern(hello_search, hello);
    require(hello_search.compile() == 0);

    const std::string sentence = "say hello to the world";
    int count = 0;
    state = 0;
    hello_search.search(sentence.begin(), sentence.end(), count_match, &count, 0, &state);
    require(count == 1);

    AhoCorasickSearch no_case_search(AhoCorasickSearch::bnfa_case::BNFA_NOCASE);
    add_pattern(no_case_search, "Needle");
    require(no_case_search.compile() == 0);

    const std::string mixed_case_text = "xx nEeDlE";
    matches.clear();
    state = 0;
    no_case_search.search(mixed_case_text.begin(), mixed_case_text.end(), collect_match, &matches, 0, &state);
    require(matches.size() == 1);
    require(matches[0] == 3);

    AhoCorasickSearch per_pattern_case_search(AhoCorasickSearch::bnfa_case::BNFA_PER_PAT_CASE);
    add_pattern(per_pattern_case_search, "Needle");
    require(per_pattern_case_search.compile() == 0);

    const std::string per_pattern_text = "needle Needle";
    matches.clear();
    state = 0;
    per_pattern_case_search.search(per_pattern_text.begin(), per_pattern_text.end(), collect_match, &matches, 0, &state);
    require(matches.size() == 1);
    require(matches[0] == 7);

    AhoCorasickSearch sparse_search;
    for (char suffix = 'a'; suffix <= 'g'; ++suffix) {
        std::string sparse_pattern = "p";
        sparse_pattern.push_back(suffix);
        add_pattern(sparse_search, sparse_pattern);
    }
    require(sparse_search.compile() == 0);

    const std::string sparse_text = "px pg";
    matches.clear();
    state = 0;
    sparse_search.search(sparse_text.begin(), sparse_text.end(), collect_match, &matches, 0, &state);
    require(matches.size() == 1);
    require(matches[0] == 3);

    AhoCorasickSearch streaming_search;
    add_pattern(streaming_search, "needle");
    require(streaming_search.compile() == 0);

    const std::string first_chunk = "xx nee";
    const std::string second_chunk = "dle yy";
    count = 0;
    state = 0;
    streaming_search.search(first_chunk.begin(), first_chunk.end(), count_match, &count, 0, &state);
    streaming_search.search(second_chunk.begin(), second_chunk.end(), count_match, &count, 0, &state);
    require(count == 1);

    AhoCorasickSearch split_per_pattern_case_search(AhoCorasickSearch::bnfa_case::BNFA_PER_PAT_CASE);
    std::vector<char> split_pattern = {'a', 'a', 'a', 'a', 'a', 'a'};
    require(split_per_pattern_case_search.addPattern(split_pattern.begin(), split_pattern.end(), false, nullptr) == 0);
    require(split_per_pattern_case_search.compile() == 0);

    std::vector<char> split_first_chunk = {'a', 'a', 'a'};
    std::vector<char> split_second_chunk = {'a', 'a', 'a'};
    count = 0;
    state = 0;
    split_per_pattern_case_search.search(
        split_first_chunk.begin(), split_first_chunk.end(), count_match, &count, 0, &state);
    split_per_pattern_case_search.search(
        split_second_chunk.begin(), split_second_chunk.end(), count_match, &count, 0, &state);
    require(count == 0);

    AhoCorasickSearch split_per_pattern_nocase_search(AhoCorasickSearch::bnfa_case::BNFA_PER_PAT_CASE);
    add_pattern(split_per_pattern_nocase_search, "Needle", true);
    require(split_per_pattern_nocase_search.compile() == 0);

    count = 0;
    state = 0;
    split_per_pattern_nocase_search.search(first_chunk.begin(), first_chunk.end(), count_match, &count, 0, &state);
    split_per_pattern_nocase_search.search(second_chunk.begin(), second_chunk.end(), count_match, &count, 0, &state);
    require(count == 1);

    AhoCorasickSearch optimized_search;
    optimized_search.setOptimizeFailureStates(true);
    add_pattern(optimized_search, "he");
    add_pattern(optimized_search, "hers");
    require(optimized_search.compile() == 0);

    const std::string optimized_text = "hers";
    count = 0;
    state = 0;
    optimized_search.search(optimized_text.begin(), optimized_text.end(), count_match, &count, 0, &state);
    require(count == 2);

    AhoCorasickSearch terminating_search;
    add_pattern(terminating_search, "a");
    require(terminating_search.compile() == 0);

    const std::string repeated_text = "aaa";
    matches.clear();
    state = 0;
    require(terminating_search.search(
               repeated_text.begin(), repeated_text.end(), stop_after_first_match, &matches, 0, &state) == 1);
    require(matches.size() == 1);

    AhoCorasickSearch overlapping_search;
    add_pattern(overlapping_search, "he", false, 1);
    add_pattern(overlapping_search, "she", false, 2);
    add_pattern(overlapping_search, "hers", false, 3);
    require(overlapping_search.compile() == 0);

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
    require(identified_matches.size() == 3);
    require(has_match(identified_matches, {1, 2}));
    require(has_match(identified_matches, {2, 1}));
    require(has_match(identified_matches, {3, 2}));

    AhoCorasickSearch recompiled_search;
    add_pattern(recompiled_search, "one", false, 1);
    require(recompiled_search.compile() == 0);
    require(recompiled_search.compile() == 0);
    add_pattern(recompiled_search, "two", false, 2);
    require(recompiled_search.compile() == 0);

    const std::string recompiled_text = "one two";
    identified_matches.clear();
    state = 0;
    recompiled_search.search(
        recompiled_text.begin(),
        recompiled_text.end(),
        collect_identified_match,
        &identified_matches,
        0,
        &state);
    require(identified_matches.size() == 2);
    require(has_match(identified_matches, {1, 0}));
    require(has_match(identified_matches, {2, 4}));

    return 0;
}
