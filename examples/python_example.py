import aho_corasick_search_ext


def main() -> None:
    patterns = ["he", "she", "hers"]
    haystack = "ushers"

    search = aho_corasick_search_ext.AhoCorasick(patterns)

    print("patterns:", patterns)
    print("haystack:", haystack)
    print("matches as indexes:", search.find_matches_as_indexes(haystack))
    print("matches as strings:", search.find_matches_as_strings(haystack))
    print("match count:", search.count_matches(haystack))


if __name__ == "__main__":
    main()
