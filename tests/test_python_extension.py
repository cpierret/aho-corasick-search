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


def test_get_automaton_info():
    ac = aho_corasick_search_ext.AhoCorasick(["needle", "hay"])

    info = ac.get_automaton_info()
    assert info["pattern_count"] == 2
    assert info["state_count"] > 0
    assert info["transition_memory_bytes"] > 0
    assert info["failureless_cache_memory_bytes"] >= 0
    assert info["failureless_cache_state_count"] >= 0
    assert info["total_memory_bytes"] >= info["transition_memory_bytes"]
    assert 1 <= info["full_row_min_transitions"] <= 64
    assert isinstance(info["failureless_full_rows"], bool)
    assert info["failureless_cache_max_states"] >= 0


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
    cache_lookups = stats["failureless_cache_hits"] + stats["failureless_cache_misses"]
    assert cache_lookups <= stats["transition_calls"]
    assert stats["match_candidates"] == 2
