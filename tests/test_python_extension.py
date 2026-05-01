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


def test_search_stats_when_enabled():
    ac = aho_corasick_search_ext.AhoCorasick(["needle", "hay"])
    if not hasattr(ac, "get_search_stats"):
        return

    ac.reset_search_stats()
    assert ac.count_matches("hay needle") == 2

    stats = ac.get_search_stats()
    assert stats["transition_calls"] == len("hay needle")
    assert stats["match_state_checks"] == len("hay needle")
    assert stats["state_visits"] >= stats["transition_calls"]
    assert stats["match_candidates"] == 2
