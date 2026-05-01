# Performance Log

This log records the benchmark and profiling path used while adding the native
Python extension and tuning search performance. The goal was to make each
optimization decision measurement-driven and to separate Python binding overhead
from core Aho-Corasick search cost.

## Benchmark Setup

The comparison target was the Python benchmark suite from `~/ahocorasick_rs`,
especially `benchmarks/test_comparison.py`.

Relevant benchmark data:

- Short dataset: 10 patterns, 10,000 haystacks, 748,890 input bytes, 50,000 matches.
- Long dataset: 4,244 patterns, 100,000 haystacks, 62,984,675 input bytes, 1,605 matches.

We added a nanobind CPython extension in `python/aho_corasick_search_ext.cpp`
so the benchmark could call this library directly from Python without per-match
Python callback overhead. The exposed API includes:

- `find_matches_as_indexes(haystack)`
- `find_matches_as_strings(haystack)`
- `count_matches(haystack)`

The count-only path was useful because it measures search cost without allocating
Python result tuples.

## Baseline Python Benchmarks

The first benchmark integrated this extension into the `ahocorasick_rs`
pytest-benchmark harness and compared overlapping index matches.

Release baseline:

| Dataset | Implementation | Mean Time |
| --- | --- | ---: |
| short | this extension, count-only | 1.715 ms |
| short | this extension, indexes | 3.260 ms |
| short | `ahocorasick_rs`, indexes | 4.202 ms |
| long | `ahocorasick_rs`, indexes | 295.456 ms |
| long | this extension, indexes | 351.483 ms |
| long | this extension, count-only | 361.819 ms |

Interpretation:

- On the short dataset, this extension was already competitive.
- On the long dataset, count-only and index-returning benchmarks were close,
  so Python result allocation was not the main bottleneck.
- The long-dataset gap pointed at core native search rather than the Python
  binding layer.

## Native Sampling

We rebuilt with `RelWithDebInfo` and sampled the long count-only benchmark with
macOS `sample`.

Sample output was written to:

```sh
/tmp/cpierret-count-long.sample.txt
```

Key native sampling results:

- `16529 / 17026` samples, about 97%, were inside
  `_bnfa_search_csparse_nfa_case`.
- The dominant line was the transition lookup:
  `src/aho_corasick.h:635`, calling `_bnfa_get_next_state_csparse_nfa`.
- `PyUnicode_AsUTF8AndSize` accounted for only 12 samples.
- `std::any` and callback-related samples were negligible in the long sparse
  match case.

Conclusion:

The important hotspot was the sparse NFA transition loop, not nanobind, Python
string conversion, result allocation, or `std::any`.

## Search Counters

To quantify the hotspot, we added an opt-in profiling mode:

```sh
cmake -S . -B build-python-stats \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_PYTHON_EXTENSION=ON \
  -DENABLE_SEARCH_STATS=ON
cmake --build build-python-stats
```

When `ENABLE_SEARCH_STATS=ON`, the Python object exposes:

- `reset_search_stats()`
- `get_search_stats()`

Baseline long-dataset counters with the original compact layout:

| Counter | Value |
| --- | ---: |
| input bytes / transition calls | 62,984,675 |
| state visits | 108,580,827 |
| failure transitions | 45,596,152 |
| full row visits | 29,488,890 |
| sparse row visits | 79,091,937 |
| sparse comparisons | 236,267,860 |
| sparse comparisons per input byte | 3.75 |
| failure transitions per input byte | 0.724 |
| match candidates | 1,605 |

Interpretation:

- Search visits about 1.72 states per input byte because failure transitions are
  common.
- Most state visits are sparse rows.
- Sparse lookup performs hundreds of millions of comparisons.
- Match handling is not material for this dataset.

This split suggested two independent optimization directions:

1. Reduce sparse transition lookup cost.
2. Reduce failure-link traversal with a cached or failureless transition path.

We tuned the first option before considering the second.

## Full-Row Threshold Tuning

The compact sparse representation originally used full 256-entry rows only for:

- the root row, and
- rows with more than 63 outgoing transitions, because they cannot fit in the
  sparse row count field.

That is compact, but high-fanout sparse rows still pay binary or linear search
cost on every visit. We added a CMake cache setting:

```sh
FULL_ROW_MIN_TRANSITIONS
```

This controls when non-root rows use full 256-entry storage. Lower values spend
more memory to replace sparse lookup with direct indexing.

Example:

```sh
cmake -S . -B build-python-full8 \
  -DBUILD_PYTHON_EXTENSION=ON \
  -DFULL_ROW_MIN_TRANSITIONS=8
cmake --build build-python-full8
```

The Python object now also exposes `get_automaton_info()` so benchmark scripts
can report state count, transition memory, total memory, and the compiled
threshold.

## Threshold Sweep

We swept thresholds with Release builds, then ran focused pytest-benchmark
checks for the most useful candidates.

Long count-path sweep:

| Threshold | Mean Time | Transition Memory |
| ---: | ---: | ---: |
| 64 | 379.8 ms | 269 KB |
| 8 | 262.1 ms | 433 KB |
| 4 | 232.0 ms | 1.03 MB |
| 1 | worse than threshold 4 | 15.6 MB |

Focused long overlapping-index benchmark at threshold 4:

| Implementation | Mean Time |
| --- | ---: |
| this extension, `FULL_ROW_MIN_TRANSITIONS=4` | 231.8 ms |
| `ahocorasick_rs`, overlapping indexes | 311.4 ms |

Counters confirmed the effect was isolated to sparse lookup cost:

| Threshold | Sparse Comparisons | Transition Memory |
| ---: | ---: | ---: |
| 64 | 236,267,860 | 269,744 bytes |
| 12 | 178,777,411 | 317,960 bytes |
| 8 | 136,280,017 | 432,600 bytes |
| 4 | 33,697,470 | 1,033,360 bytes |
| 1 | 0 | 15,610,288 bytes |

Failure transitions stayed fixed at `45,596,152`, which means this knob only
changes row lookup cost. It does not hide or solve failure-link traversal.

## Decision

We set the default full-row threshold to `4`.

Rationale:

- It gave the best focused benchmark result among the tested thresholds.
- It reduced sparse comparisons by about 86% versus the compact baseline.
- It improved long-dataset overlapping-index throughput enough to beat the
  `ahocorasick_rs` benchmark run used for comparison.
- The transition table grew to about 1 MB on the long dataset, which is a
  reasonable tradeoff for this benchmark profile.
- Threshold `1` removed sparse comparisons entirely but used far more memory and
  did not improve timing, likely because cache pressure outweighed lookup gains.

To restore the old compact behavior, configure with:

```sh
-DFULL_ROW_MIN_TRANSITIONS=64
```

## Failureless Transition Path

The next independent optimization was failure traversal.

The full-row threshold reduced sparse lookup comparisons, but the long dataset
still performs `45,596,152` failure transitions, about `0.724` per input byte.
A selective cached or failureless transition path could precompute the final
transition for hot `(state, byte)` pairs or hot states, turning repeated failure
walks into direct lookups.

We implemented two variants and kept them separately configurable:

1. In-place failureless full rows.
2. A dense failureless cache for the first N compiled states.

### In-Place Full Rows

Full rows already spend 256 entries per state. We can therefore resolve missing
full-row transitions during compilation without increasing transition-table
memory. For each non-root full row, zero entries are replaced with the state that
would be reached after following failure links.

This is enabled by default:

```sh
-DENABLE_FAILURELESS_FULL_ROWS=ON
```

Use this to restore the old behavior:

```sh
-DENABLE_FAILURELESS_FULL_ROWS=OFF
```

Long-dataset stats with `FULL_ROW_MIN_TRANSITIONS=4` and in-place full-row
resolution:

| Counter | Value |
| --- | ---: |
| input bytes / transition calls | 62,984,675 |
| state visits | 77,583,296 |
| failure transitions | 14,598,621 |
| full row visits | 58,882,778 |
| sparse row visits | 18,700,518 |
| sparse comparisons | 32,897,409 |
| dense cache memory | 0 bytes |
| transition memory | 1,033,360 bytes |

Focused long overlapping-index benchmark:

| Implementation | Mean Time |
| --- | ---: |
| this extension, threshold 4 + failureless full rows | 180.4 ms |
| `ahocorasick_rs`, overlapping indexes | 316.8 ms |

This was the best result so far because it removed about 31 million failure
transitions without adding a second large transition table.

### Dense Failureless Cache

The dense cache precomputes 256 final transitions for up to
`FAILURELESS_CACHE_MAX_STATES` states:

```sh
-DFAILURELESS_CACHE_MAX_STATES=1024
```

`0` disables the dense cache and is the default.

The full dense cache removed all failure transitions on the long dataset:

| Counter | Value |
| --- | ---: |
| cached states | 11,163 |
| failure transitions | 0 |
| cache hits | 62,984,675 |
| cache memory | 23,895,184 bytes |

However, it was slower in the focused long overlapping-index benchmark:

| Configuration | Mean Time |
| --- | ---: |
| threshold 4 + failureless full rows | 180.4 ms |
| threshold 4 + failureless full rows + full dense cache | 287.1 ms |

The dense cache removes more algorithmic work, but its larger random-access
table adds enough memory pressure to lose on this benchmark. It remains useful
as an opt-in experiment for other pattern sets or machines, but it should not be
enabled by default based on the current evidence.
