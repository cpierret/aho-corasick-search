import aho_corasick_search_ext


def test_find_matches_as_indexes():
    ac = aho_corasick_search_ext.AhoCorasick(["he", "she", "hers"])

    assert sorted(ac.find_matches_as_indexes("ushers")) == [
        (0, 2, 4),
        (1, 1, 4),
        (2, 2, 6),
    ]


def test_find_matches_as_strings():
    ac = aho_corasick_search_ext.AhoCorasick(["needle", "hay"])

    assert ac.find_matches_as_strings(b"hay needle") == ["hay", "needle"]


def test_count_matches():
    ac = aho_corasick_search_ext.AhoCorasick(["needle", "hay"])

    assert ac.count_matches("hay needle") == 2
