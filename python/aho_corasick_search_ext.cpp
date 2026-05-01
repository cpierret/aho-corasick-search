#include "aho_corasick.h"

#include <Python.h>
#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/tuple.h>
#include <nanobind/stl/vector.h>

#include <cstddef>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace nb = nanobind;
using namespace nb::literals;

namespace {

class HaystackView {
public:
    explicit HaystackView(nb::handle haystack)
    {
        PyObject* object = haystack.ptr();

        if (PyUnicode_Check(object))
        {
            Py_ssize_t size = 0;
            const char* data = PyUnicode_AsUTF8AndSize(object, &size);
            if (!data)
            {
                throw nb::python_error();
            }
            data_ = data;
            size_ = size;
            return;
        }

        if (PyBytes_Check(object))
        {
            char* data = nullptr;
            Py_ssize_t size = 0;
            if (PyBytes_AsStringAndSize(object, &data, &size) < 0)
            {
                throw nb::python_error();
            }
            data_ = data;
            size_ = size;
            return;
        }

        if (PyObject_GetBuffer(object, &buffer_, PyBUF_SIMPLE) == 0)
        {
            owns_buffer_ = true;
            data_ = static_cast<const char*>(buffer_.buf);
            size_ = buffer_.len;
            return;
        }

        PyErr_Clear();
        throw nb::type_error("haystack must be str, bytes, or a contiguous bytes-like object");
    }

    HaystackView(const HaystackView&) = delete;
    HaystackView& operator=(const HaystackView&) = delete;

    ~HaystackView()
    {
        if (owns_buffer_)
        {
            PyBuffer_Release(&buffer_);
        }
    }

    const char* begin() const
    {
        return data_;
    }

    const char* end() const
    {
        return data_ + size_;
    }

private:
    Py_buffer buffer_ {};
    bool owns_buffer_ = false;
    const char* data_ = nullptr;
    Py_ssize_t size_ = 0;
};

using MatchTuple = std::tuple<std::size_t, int, int>;

struct IndexMatchCollector {
    const std::vector<std::size_t>* pattern_lengths = nullptr;
    std::vector<MatchTuple> matches;
};

struct PatternMatchCollector {
    std::vector<std::size_t> pattern_ids;
};

int collect_index_match(
    textsearch::AhoCorasickSearch::any_t pattern_userdata,
    int index,
    textsearch::AhoCorasickSearch::any_t search_userdata)
{
    auto* collector = std::any_cast<IndexMatchCollector*>(search_userdata);
    const auto pattern_id = std::any_cast<std::size_t>(pattern_userdata);
    const auto length = collector->pattern_lengths->at(pattern_id);
    collector->matches.emplace_back(pattern_id, index, index + static_cast<int>(length));
    return 0;
}

int collect_pattern_match(
    textsearch::AhoCorasickSearch::any_t pattern_userdata,
    int,
    textsearch::AhoCorasickSearch::any_t search_userdata)
{
    auto* collector = std::any_cast<PatternMatchCollector*>(search_userdata);
    collector->pattern_ids.push_back(std::any_cast<std::size_t>(pattern_userdata));
    return 0;
}

int count_match(
    textsearch::AhoCorasickSearch::any_t,
    int,
    textsearch::AhoCorasickSearch::any_t search_userdata)
{
    auto* count = std::any_cast<std::size_t*>(search_userdata);
    ++(*count);
    return 0;
}

#ifdef AHO_CORASICK_SEARCH_STATS
nb::dict search_stats_to_dict(const textsearch::AhoCorasickSearch::SearchStats& stats)
{
    nb::dict result;
    result["transition_calls"] = stats.transition_calls;
    result["state_visits"] = stats.state_visits;
    result["full_row_visits"] = stats.full_row_visits;
    result["full_root_transitions"] = stats.full_root_transitions;
    result["full_root_zero_transitions"] = stats.full_root_zero_transitions;
    result["full_non_root_hits"] = stats.full_non_root_hits;
    result["full_non_root_misses"] = stats.full_non_root_misses;
    result["sparse_row_visits"] = stats.sparse_row_visits;
    result["sparse_linear_rows"] = stats.sparse_linear_rows;
    result["sparse_linear_comparisons"] = stats.sparse_linear_comparisons;
    result["sparse_linear_hits"] = stats.sparse_linear_hits;
    result["sparse_linear_misses"] = stats.sparse_linear_misses;
    result["sparse_binary_rows"] = stats.sparse_binary_rows;
    result["sparse_binary_comparisons"] = stats.sparse_binary_comparisons;
    result["sparse_binary_hits"] = stats.sparse_binary_hits;
    result["sparse_binary_misses"] = stats.sparse_binary_misses;
    result["failure_transitions"] = stats.failure_transitions;
    result["failureless_cache_hits"] = stats.failureless_cache_hits;
    result["failureless_cache_misses"] = stats.failureless_cache_misses;
    result["match_state_checks"] = stats.match_state_checks;
    result["match_state_hits"] = stats.match_state_hits;
    result["match_candidates"] = stats.match_candidates;
    return result;
}
#endif

class PyAhoCorasick {
public:
    explicit PyAhoCorasick(const std::vector<std::string>& patterns)
        : patterns_(patterns),
          search_(textsearch::AhoCorasickSearch::bnfa_case::BNFA_CASE)
    {
        if (patterns_.empty())
        {
            throw nb::value_error("at least one pattern is required");
        }

        pattern_lengths_.reserve(patterns_.size());
        for (std::size_t index = 0; index < patterns_.size(); ++index)
        {
            const std::string& pattern = patterns_[index];
            if (pattern.empty())
            {
                throw nb::value_error("empty patterns are not supported");
            }
            pattern_lengths_.push_back(pattern.size());
            if (search_.addPattern(pattern.begin(), pattern.end(), false, index) != 0)
            {
                throw std::runtime_error("failed to add pattern");
            }
        }

        if (search_.compile() != 0)
        {
            throw std::runtime_error("failed to compile automaton");
        }
    }

    std::vector<MatchTuple> find_matches_as_indexes(nb::handle haystack)
    {
        HaystackView view(haystack);
        IndexMatchCollector collector;
        collector.pattern_lengths = &pattern_lengths_;

        {
            nb::gil_scoped_release release;
            textsearch::AhoCorasickSearch::bnfa_state_index_t state = 0;
            search_.search(
                view.begin(),
                view.end(),
                collect_index_match,
                &collector,
                0,
                &state);
        }

        return std::move(collector.matches);
    }

    std::vector<std::string> find_matches_as_strings(nb::handle haystack)
    {
        HaystackView view(haystack);
        PatternMatchCollector collector;

        {
            nb::gil_scoped_release release;
            textsearch::AhoCorasickSearch::bnfa_state_index_t state = 0;
            search_.search(
                view.begin(),
                view.end(),
                collect_pattern_match,
                &collector,
                0,
                &state);
        }

        std::vector<std::string> matches;
        matches.reserve(collector.pattern_ids.size());
        for (std::size_t pattern_id : collector.pattern_ids)
        {
            matches.push_back(patterns_.at(pattern_id));
        }
        return matches;
    }

    std::size_t count_matches(nb::handle haystack)
    {
        HaystackView view(haystack);
        std::size_t count = 0;

        {
            nb::gil_scoped_release release;
            textsearch::AhoCorasickSearch::bnfa_state_index_t state = 0;
            search_.search(view.begin(), view.end(), count_match, &count, 0, &state);
        }

        return count;
    }

    nb::dict get_automaton_info() const
    {
        nb::dict result;
        result["pattern_count"] = search_.getPatternCount();
        result["state_count"] = search_.getStateCount();
        result["transition_memory_bytes"] = search_.getTransitionMemoryBytes();
        result["failureless_cache_memory_bytes"] = search_.getFailurelessCacheMemoryBytes();
        result["failureless_cache_state_count"] = search_.getFailurelessCacheStateCount();
        result["total_memory_bytes"] = search_.getTotalMemoryBytes();
        result["full_row_min_transitions"] =
            textsearch::AhoCorasickSearch::getFullRowMinTransitions();
        result["failureless_full_rows"] =
            textsearch::AhoCorasickSearch::hasFailurelessFullRows();
        result["sparse_failureless_max_transitions"] =
            textsearch::AhoCorasickSearch::getSparseFailurelessMaxTransitions();
        result["failureless_cache_max_states"] =
            textsearch::AhoCorasickSearch::getFailurelessCacheMaxStates();
        return result;
    }

#ifdef AHO_CORASICK_SEARCH_STATS
    void reset_search_stats()
    {
        search_.resetSearchStats();
    }

    nb::dict get_search_stats() const
    {
        return search_stats_to_dict(search_.getSearchStats());
    }
#endif

private:
    std::vector<std::string> patterns_;
    std::vector<std::size_t> pattern_lengths_;
    textsearch::AhoCorasickSearch search_;
};

} // namespace

NB_MODULE(aho_corasick_search_ext, module)
{
    module.doc() = "Native CPython bindings for AhoCorasickSearch.";

    nb::class_<PyAhoCorasick>(module, "AhoCorasick")
        .def(nb::init<const std::vector<std::string>&>(), "patterns"_a)
        .def(
            "find_matches_as_indexes",
            &PyAhoCorasick::find_matches_as_indexes,
            "haystack"_a,
            "Return (pattern_index, start_byte, end_byte) tuples.")
        .def(
            "find_matches_as_strings",
            &PyAhoCorasick::find_matches_as_strings,
            "haystack"_a,
            "Return matched pattern strings.")
        .def(
            "count_matches",
            &PyAhoCorasick::count_matches,
            "haystack"_a,
            "Return the number of matches without allocating match result tuples.")
        .def(
            "get_automaton_info",
            &PyAhoCorasick::get_automaton_info,
            "Return compiled automaton size and layout information.")
#ifdef AHO_CORASICK_SEARCH_STATS
        .def(
            "reset_search_stats",
            &PyAhoCorasick::reset_search_stats,
            "Reset native search instrumentation counters.")
        .def(
            "get_search_stats",
            &PyAhoCorasick::get_search_stats,
            "Return native search instrumentation counters.")
#endif
        ;
}
