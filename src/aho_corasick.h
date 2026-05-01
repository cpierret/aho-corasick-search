/*
** aho_corasick.h
**
** Basic NFA based multi-pattern search using Aho_corasick construction,
** and compacted sparse storage. C++ Version.
**
** author: Christophe Pierret
** Copyright 2016 Christophe Pierret
**
** Transcoded in C++ based on bnfa_search.c/h 
** Thread-safety: remove any global variable
** Type-safety: remove unsafe pointer casts
** Duplicate code factorisation
** Genericity: accepts any char/unsigned char random access iterators
**
** Based on version 3.0 of bnfa_search from Snort
**
** author: marc norton
** date:   12/21/05
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2005-2013 Sourcefire, Inc.
**
** LICENSE (GPL)
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
** USA
*/
#pragma once

#ifndef BNFA_SEARCH_H
#define BNFA_SEARCH_H

#include <limits.h>
#include <stdint.h>
#include <cstddef>
#include <memory>
#include <set>
#include <algorithm>
#include <any>
#include <iterator>
#include <new>
#include <vector>


#include "uppercase_iterator.h"

// forcing inlining of _bnfa_get_next_state_csparse_nfa is key to performance
#ifdef _MSC_VER
// Microsoft Visual C++
# define FORCE_INLINE __forceinline
#else
# ifdef __GNUG__
// GCC C++
#  define FORCE_INLINE inline __attribute__((always_inline))
# else
#  define FORCE_INLINE inline
# endif
#endif

// define this to have more than 16 millions states
#define BNFA_STATE_64BITS

#ifndef AHO_CORASICK_FULL_ROW_MIN_TRANSITIONS
#define AHO_CORASICK_FULL_ROW_MIN_TRANSITIONS 4
#endif

#ifndef AHO_CORASICK_FAILURELESS_CACHE_MAX_STATES
#define AHO_CORASICK_FAILURELESS_CACHE_MAX_STATES 0
#endif

#ifndef AHO_CORASICK_FAILURELESS_FULL_ROWS
#define AHO_CORASICK_FAILURELESS_FULL_ROWS 1
#endif

namespace textsearch {


/*
*   Aho-Corasick State Machine Struct
*/
class AhoCorasickSearch {
public:
    using any_t = std::any;
    typedef int(*match_function_ptr_t)(any_t pattern_userdata, int index, any_t search_userdata);
#ifdef BNFA_STATE_64BITS
    typedef uint64_t bnfa_state_t;
    typedef uint_least64_t  bnfa_state_index_t;
#else
    typedef uint32_t bnfa_state_t;
    typedef uint_least32_t bnfa_state_index_t;
#endif
    enum class bnfa_case : int {
        BNFA_PER_PAT_CASE, // DEFAULT:case-sensitivity is specified per pattern
        BNFA_CASE,         // binary search (case sensitive), fastest mode
        BNFA_NOCASE        // case-insensitive search
    };

#ifdef AHO_CORASICK_SEARCH_STATS
    struct SearchStats {
        uint64_t transition_calls = 0;
        uint64_t state_visits = 0;
        uint64_t full_row_visits = 0;
        uint64_t full_root_transitions = 0;
        uint64_t full_root_zero_transitions = 0;
        uint64_t full_non_root_hits = 0;
        uint64_t full_non_root_misses = 0;
        uint64_t sparse_row_visits = 0;
        uint64_t sparse_linear_rows = 0;
        uint64_t sparse_linear_comparisons = 0;
        uint64_t sparse_linear_hits = 0;
        uint64_t sparse_linear_misses = 0;
        uint64_t sparse_binary_rows = 0;
        uint64_t sparse_binary_comparisons = 0;
        uint64_t sparse_binary_hits = 0;
        uint64_t sparse_binary_misses = 0;
        uint64_t failure_transitions = 0;
        uint64_t failureless_cache_hits = 0;
        uint64_t failureless_cache_misses = 0;
        uint64_t match_state_checks = 0;
        uint64_t match_state_hits = 0;
        uint64_t match_candidates = 0;
    };

    void resetSearchStats()
    {
        search_stats_ = SearchStats {};
    }

    SearchStats getSearchStats() const
    {
        return search_stats_;
    }
#endif

    void setCase(bnfa_case flag);


    explicit AhoCorasickSearch(bnfa_case flag = bnfa_case::BNFA_CASE);
    ~AhoCorasickSearch();
    
    void setOptimizeFailureStates(bool flag=true);

    //
    // Add a pattern to search
    //   patBegin,patEnd: are char/unsigned char iterators
    //                    specifying the pattern.
    //   nocase: if true, case insensitive search
    //           otherwise binary search
    //           Behavior is dependent on the case mode
    //           if BNFA_NOCASE or BNFA_CASE, this setting is ignored
    //   userdata: a pointer to user-specific data associated to pattern
    template<typename RAIterator>
    int addPattern(
        RAIterator patBegin,
        RAIterator patEnd,
        bool nocase,
        any_t userdata
        );

    int compile();

    // current_state is optional for single-buffer searches. Pass the same
    // non-null state pointer across calls to continue matching across buffers.
    // In BNFA_PER_PAT_CASE, case-sensitive patterns that begin before the
    // current buffer cannot be exact-case verified and are not reported.
    template<typename RAIterator>
    unsigned search(RAIterator begin, RAIterator end,
        match_function_ptr_t match,
        any_t userdata,
        bnfa_state_index_t sindex,
        bnfa_state_index_t* current_state);

    int getPatternCount() const;
    bnfa_state_index_t getStateCount() const;
    size_t getTransitionMemoryBytes() const;
    size_t getFailurelessCacheMemoryBytes() const;
    size_t getFailurelessCacheStateCount() const;
    size_t getTotalMemoryBytes() const;
    static constexpr unsigned getFullRowMinTransitions()
    {
        return BNFA_FULL_ROW_MIN_TRANSITIONS;
    }
    static constexpr size_t getFailurelessCacheMaxStates()
    {
        return BNFA_FAILURELESS_CACHE_MAX_STATES;
    }
    static constexpr bool hasFailurelessFullRows()
    {
        return BNFA_FAILURELESS_FULL_ROWS;
    }

    void print(); /* prints the nfa states-verbose!! */
    void printInfo(); /* print info on this search engine */
    void printInfoEx(char * text);
private:

    // not copyable
    AhoCorasickSearch(const AhoCorasickSearch&);
    void operator=(const AhoCorasickSearch&);

    /*
    *   DEFINES and Typedef's
    */
#ifdef BNFA_STATE_64BITS

    static constexpr bnfa_state_t BNFA_SPARSE_MAX_STATE = 0x00ffffffffffffff;
    static constexpr unsigned BNFA_SPARSE_COUNT_SHIFT = 56;
    static constexpr unsigned BNFA_SPARSE_VALUE_SHIFT = 56;

    static constexpr bnfa_state_t BNFA_SPARSE_MATCH_BIT = 0x8000000000000000;
    static constexpr bnfa_state_t BNFA_SPARSE_FULL_BIT = 0x4000000000000000;
    static constexpr bnfa_state_t BNFA_SPARSE_COUNT_BITS = 0x3f00000000000000;
    static constexpr unsigned BNFA_SPARSE_MAX_ROW_TRANSITIONS = 0x3f;
    static constexpr bnfa_state_t BNFA_SPARSE_CONTROL_BITS = 0xff00000000000000; // control Word
    static constexpr bnfa_state_t BNFA_SPARSE_CHAR_BITS = 0xff00000000000000; // next words
    /*
    * Used to initialize last state, states are limited to 56 bits
    * so this will not conflict.
    */
    static constexpr bnfa_state_t LAST_STATE_INIT = 0xffffffffffffffff;
    static constexpr bnfa_state_t BNFA_FAIL_STATE = 0xffffffffffffffff;

#else

    static constexpr bnfa_state_index_t BNFA_SPARSE_MAX_STATE = 0x00ffffff;
    static constexpr unsigned BNFA_SPARSE_COUNT_SHIFT = 24;
    static constexpr unsigned BNFA_SPARSE_VALUE_SHIFT = 24;

    static constexpr bnfa_state_index_t BNFA_SPARSE_MATCH_BIT = 0x80000000;
    static constexpr bnfa_state_index_t BNFA_SPARSE_FULL_BIT = 0x40000000;
    static constexpr bnfa_state_index_t BNFA_SPARSE_COUNT_BITS = 0x3f000000;
    static constexpr unsigned BNFA_SPARSE_MAX_ROW_TRANSITIONS = 0x3f;
    static constexpr bnfa_state_index_t BNFA_SPARSE_CONTROL_BITS = 0xff000000; // control Word
    static constexpr bnfa_state_index_t BNFA_SPARSE_CHAR_BITS = 0xff000000; // next words
    /*
    * Used to initialize last state, states are limited to 0-16M
    * so this will not conflict.
    */
    static constexpr bnfa_state_index_t LAST_STATE_INIT = 0xffffffff;
    static constexpr bnfa_state_t BNFA_FAIL_STATE      = 0xffffffff;

#endif

    static constexpr unsigned BNFA_SPARSE_LINEAR_SEARCH_LIMIT = 6;
    static constexpr unsigned BNFA_MAX_ALPHABET_SIZE = 256;
    static constexpr unsigned BNFA_FULL_ROW_MIN_TRANSITIONS =
        AHO_CORASICK_FULL_ROW_MIN_TRANSITIONS;
    static constexpr size_t BNFA_FAILURELESS_CACHE_MAX_STATES =
        AHO_CORASICK_FAILURELESS_CACHE_MAX_STATES;
    static constexpr bool BNFA_FAILURELESS_FULL_ROWS =
        AHO_CORASICK_FAILURELESS_FULL_ROWS != 0;
    static_assert(
        BNFA_FULL_ROW_MIN_TRANSITIONS >= 1 &&
            BNFA_FULL_ROW_MIN_TRANSITIONS <= BNFA_SPARSE_MAX_ROW_TRANSITIONS + 1,
        "AHO_CORASICK_FULL_ROW_MIN_TRANSITIONS must be between 1 and 64");

 
    /*
    *   Internal Pattern Representation
    */

    struct bnfa_pattern {
        bnfa_pattern* next = nullptr;

        std::vector<unsigned char> casepatrn; /* case specific */
        unsigned                   n = 0;     /* pattern len */
        bool                       nocase = false; /* nocase flag */
        any_t                      userdata;  /* ptr to users pattern data/info  */

    };
    using bnfa_pattern_t = bnfa_pattern;

    /*
    *  List format transition node
    */
    struct bnfa_trans_node_s {
        unsigned int       key = 0; // 8 bit character
        bnfa_state_index_t next_state = 0;
        bnfa_trans_node_s* next = nullptr;

    };
    using bnfa_trans_node_t = bnfa_trans_node_s;

    /*
    *  List format patterns
    */
    struct bnfa_match_node_s {
        bnfa_pattern_t* data = nullptr;
        bnfa_match_node_s* next = nullptr;

    };
    using bnfa_match_node_t = bnfa_match_node_s;

    /*
    *  Final storage type for the state transitions
    */
    enum {
        BNFA_FULL, // not implemented
        BNFA_SPARSE
    };

    struct bnfa_match_s {
        bnfa_match_node_t * data;
        int pos;
        friend bool operator< (const bnfa_match_s &a, const bnfa_match_s &b)
        {
            return a.pos < b.pos || (a.pos == b.pos && a.data<b.data);
        }
        friend bool operator> (const bnfa_match_s &a, const bnfa_match_s &b)
        {
            return a.pos > b.pos || (a.pos == b.pos && a.data>b.data);
        }
        friend bool operator== (const bnfa_match_s &a, const bnfa_match_s &b)
        {
            return a.pos == b.pos && a.data == b.data;
        }
    };

    template <typename RAIterator>
    class match_function_functor_check {
    public:
        match_function_functor_check(
            match_function_ptr_t userfunc, 
            RAIterator begin, 
            RAIterator end,
            bool check=false
            ) : userfunc_(userfunc), begin_(begin), end_(end), check_(check) {}
        int operator() (
            any_t pattern_userdata, 
            int index, 
            any_t search_userdata, 
            bnfa_pattern_t* pattern,
            bool starts_before_buffer=false
            )
        {
            if (check_ && !pattern->nocase)
            {
                if (starts_before_buffer || index < 0)
                    return 0;

                RAIterator pattern_begin = begin_ + index;
                using difference_type = typename std::iterator_traits<RAIterator>::difference_type;
                if (end_ - pattern_begin < static_cast<difference_type>(pattern->n))
                    return 0;

                if (std::equal(
                        pattern->casepatrn.data(),
                        pattern->casepatrn.data() + pattern->n,
                        pattern_begin
                        )
                    )
                    return userfunc_(pattern_userdata, index, search_userdata);
                else
                    return 0;
            }
            return userfunc_(pattern_userdata, index, search_userdata);
        }
    private:
        match_function_ptr_t userfunc_;
        RAIterator begin_;
        RAIterator end_;
        bool check_;
    };

    typedef struct bnfa_match_s bnfa_match_t;

    int                bnfaMethod;
    bnfa_case          bnfaCaseMode;
    int                bnfaFormat;
    unsigned           bnfaAlphabetSize;
    bool               bnfaOptimizeFailureStates;

    unsigned           bnfaPatternCnt;
    bnfa_pattern_t*    bnfaPatterns;

    size_t             bnfaMaxStates;
    bnfa_state_index_t bnfaNumStates;
    unsigned           bnfaNumTrans;
    unsigned           bnfaMatchStates;

    struct bnfa_trans_table {
        std::vector<bnfa_state_t> states;             // zero state transitions
        std::vector<bnfa_trans_node_t*> transitions;  // per state transition lists
    };
    using bnfa_trans_table_t = bnfa_trans_table;

    std::unique_ptr<bnfa_trans_table_t> bnfaTransTable;

    std::vector<bnfa_match_node_t*> bnfaMatchList;
    std::vector<bnfa_state_index_t> bnfaFailState;

    std::vector<bnfa_state_t> bnfaTransList;
    std::vector<size_t> failureless_cache_offsets_;
    std::vector<bnfa_state_index_t> failureless_transition_cache_;
    int                bnfaForceFullZeroState;

    std::vector<std::unique_ptr<bnfa_pattern_t>> pattern_storage_;
    std::vector<std::unique_ptr<bnfa_trans_node_t>> transition_node_storage_;
    std::vector<std::unique_ptr<bnfa_match_node_t>> match_node_storage_;

#ifdef AHO_CORASICK_SEARCH_STATS
    SearchStats search_stats_;
#endif

    size_t 			   bnfa_memory;
    size_t 			   pat_memory;
    size_t 			   list_memory;
    size_t 			   nextstate_memory;
    size_t             failureless_cache_memory;
    size_t 			   failstate_memory;
    size_t 			   matchlist_memory;
    character_functor toupper_functor;
    typedef std::set<bnfa_match_t> match_queue_type;
    match_queue_type match_queue;
    size_t max_queue;
    inline void _init_queue()
    {
        match_queue.clear();
    }
    int _add_queue(bnfa_match_node_t * p, int pos);

    template <typename RAIteratorUnderlying,typename RAIterator>
    unsigned _process_queue(match_function_functor_check<RAIteratorUnderlying> functor, any_t data, RAIterator begin);

    int 
    _bnfa_list_put_next_state(
        bnfa_state_index_t state, 
        unsigned char input, 
        bnfa_state_index_t next_state
        );

    int _bnfa_list_free_table();
    
    bnfa_state_index_t 
        _bnfa_list_get_next_state(bnfa_state_index_t state, unsigned char input);

    ptrdiff_t _bnfa_list_conv_row_to_full(bnfa_state_index_t state, bnfa_state_t * full);
    int _bnfa_add_pattern_states(bnfa_pattern_t * p);
    int _bnfa_opt_nfa();
    int _bnfa_build_nfa();
    int _bnfa_conv_list_to_csparse_array();
    int _resolve_full_row_failure_transitions();
    int _build_failureless_transition_cache(const std::vector<bnfa_state_index_t>& state_indexes);
    void _reset_compiled_state();
    bnfa_trans_node_t* _make_transition_node();
    bnfa_match_node_t* _make_match_node();
    
    template <typename RAIteratorUnderlying,typename RAIterator>
    unsigned _bnfa_search_csparse_nfa_q(RAIterator begin, RAIterator end,
        match_function_functor_check<RAIteratorUnderlying> match_functor,
        any_t data, bnfa_state_index_t sindex, bnfa_state_index_t *current_state);
    
    template <typename RAIteratorUnderlying, typename RAIterator>
    unsigned _bnfa_search_csparse_nfa_case(RAIterator begin, RAIterator end,
        match_function_functor_check<RAIteratorUnderlying> match_functor,
        any_t data, bnfa_state_index_t sindex, bnfa_state_index_t *current_state);
    
    static size_t _bnfa_conv_node_to_full(bnfa_trans_node_t* t, bnfa_state_t * full);
    
    static int KcontainsJ(bnfa_trans_node_t * tk, bnfa_trans_node_t *tj);

    static inline bool shouldUseFullFormatForRow(
        bnfa_state_index_t state,
        unsigned transition_count,
        int force_full_zero_state)
    {
        return (state == 0 && force_full_zero_state) ||
            transition_count >= BNFA_FULL_ROW_MIN_TRANSITIONS ||
            transition_count > BNFA_SPARSE_MAX_ROW_TRANSITIONS;
    }
    
    static FORCE_INLINE bnfa_state_index_t _bnfa_get_next_state_csparse_nfa(
        bnfa_state_t * pcx,
        bnfa_state_index_t sindex,
        unsigned input
#ifdef AHO_CORASICK_SEARCH_STATS
        , SearchStats* stats
#endif
        );

    static FORCE_INLINE bnfa_state_index_t _bnfa_get_next_state_failureless_nfa(
        bnfa_state_t * pcx,
        const size_t* failureless_cache_offsets,
        const bnfa_state_index_t* failureless_transition_cache,
        bnfa_state_index_t sindex,
        unsigned input
#ifdef AHO_CORASICK_SEARCH_STATS
        , SearchStats* stats
#endif
        );


    static
        inline
        bnfa_state_index_t sparseGetTransitionState(bnfa_state_t state) {
        return  state & BNFA_SPARSE_MAX_STATE;
    }

    static
    inline
    bnfa_state_index_t getFailureState(bnfa_state_t state) {
        return  state & BNFA_SPARSE_MAX_STATE;
    }

    static
        inline
        bnfa_state_index_t getCurrentState(bnfa_state_t state) {
        return  state; // &BNFA_SPARSE_MAX_STATE; not needed
    }

    static 
    inline 
    unsigned int sparseGetNumberOfTransitions(bnfa_state_t state) {
        return ( state>> BNFA_SPARSE_COUNT_SHIFT)
            & BNFA_SPARSE_MAX_ROW_TRANSITIONS;
    }
    
    static 
    inline 
    bnfa_state_index_t fullGetTransitionState(bnfa_state_t state) {
        return  state & BNFA_SPARSE_MAX_STATE;
    }
    
    static
    inline 
    bool isFullFormat(bnfa_state_t state) {
        return (state & BNFA_SPARSE_FULL_BIT)!=0;
    }

    static
        inline
        bnfa_state_t 
        makeControlState(bnfa_state_t control_bits, bnfa_state_index_t failure_state) {
            return (control_bits & BNFA_SPARSE_CONTROL_BITS) |
            (failure_state & BNFA_SPARSE_MAX_STATE);
    }
    
    static
        inline
        bnfa_state_t
        makeTransitionState(bnfa_state_t char_bits, bnfa_state_index_t transition_state) {
        return (char_bits & BNFA_SPARSE_CHAR_BITS) |
            (transition_state & BNFA_SPARSE_MAX_STATE);
    }
    static inline bool isMatchState(bnfa_state_t state) {
        return (state & BNFA_SPARSE_MATCH_BIT)!=0;
    }

    static inline int _bnfa_binearch(
        bnfa_state_t * a,
        int a_len,
        bnfa_state_t val
#ifdef AHO_CORASICK_SEARCH_STATS
        , SearchStats* stats
#endif
        )
    {
        int m, l, r;
        bnfa_state_t c;
        l = 0;
        r = a_len - 1;
        while (r >= l)
        {
            m = (r + l) >> 1;
            c = a[m] >> BNFA_SPARSE_VALUE_SHIFT;
#ifdef AHO_CORASICK_SEARCH_STATS
            ++stats->sparse_binary_comparisons;
#endif
            if (val == c)
            {
                return m;
            }
            else if (val <  c)
            {
                r = m - 1;
            }
            else /* val > c */
            {
                l = m + 1;
            }
        }
        return -1;
    }
};

template<typename RAIterator>
unsigned
AhoCorasickSearch::search(RAIterator begin, RAIterator end,
    match_function_ptr_t Match,
    any_t userdata, bnfa_state_index_t sindex, bnfa_state_index_t* current_state)
{
    int ret = 0;
    bnfa_state_index_t local_state = sindex;

    if (current_state)
    {
        local_state = *current_state;
    }

    if (bnfaCaseMode == bnfa_case::BNFA_PER_PAT_CASE)
    {
        functor_iterator<character_functor, RAIterator> itBegin(toupper_functor, begin);
        functor_iterator<character_functor, RAIterator> itEnd(toupper_functor, end);
        if (bnfaMethod)
        {
            ret = _bnfa_search_csparse_nfa_case(
                itBegin, 
                itEnd, 
                match_function_functor_check<RAIterator>(Match, begin, end, true),
                userdata, 
                local_state,
                &local_state
                );
        }
        else
        {
            ret = _bnfa_search_csparse_nfa_q(
                itBegin, 
                itEnd, 
                match_function_functor_check<RAIterator>(Match, begin, end, true),
                userdata,
                local_state,
                &local_state
                );
        }
    }
    else if (bnfaCaseMode == bnfa_case::BNFA_CASE)
    {
        ret = _bnfa_search_csparse_nfa_case(
            begin, 
            end, 
            match_function_functor_check<RAIterator>(Match, begin, end, false),
            userdata, 
            local_state,
            &local_state
            );
    }
    else/* NOCASE */
    {
        functor_iterator<character_functor, RAIterator> itBegin(toupper_functor, begin);
        functor_iterator<character_functor, RAIterator> itEnd(toupper_functor, end);
        ret = _bnfa_search_csparse_nfa_case(
            itBegin, 
            itEnd, 
            match_function_functor_check<RAIterator>(Match, begin, end, false),
            userdata, 
            local_state,
            &local_state
            );
    }
    if (current_state)
    {
        *current_state = local_state;
    }
    return ret;
}

template<typename RAIteratorUnderlying,typename RAIterator>
unsigned
AhoCorasickSearch::_bnfa_search_csparse_nfa_q(RAIterator begin, RAIterator Tend,
    match_function_functor_check<RAIteratorUnderlying> match_functor,
    any_t userdata, bnfa_state_index_t sindex, bnfa_state_index_t *current_state)
{
    bnfa_match_node_t  * mlist;
    RAIterator T = begin;

    bnfa_match_node_t ** MatchList = bnfaMatchList.data();
    bnfa_state_t       * transList = bnfaTransList.data();
#if AHO_CORASICK_FAILURELESS_CACHE_MAX_STATES > 0
    const size_t* failureless_cache_offsets = failureless_cache_offsets_.data();
    const bnfa_state_index_t* failureless_transition_cache = failureless_transition_cache_.data();
#endif
    bnfa_state_index_t   last_sindex;
    unsigned int nfound = 0;

    _init_queue();

    for (; T<Tend; ++T)
    {
        last_sindex = sindex;

        /* Transition to next state index */
#if AHO_CORASICK_FAILURELESS_CACHE_MAX_STATES > 0
        sindex = _bnfa_get_next_state_failureless_nfa(
            transList,
            failureless_cache_offsets,
            failureless_transition_cache,
            sindex,
            static_cast<unsigned char>(*T)
#ifdef AHO_CORASICK_SEARCH_STATS
            , &search_stats_
#endif
            );
#else
        sindex = _bnfa_get_next_state_csparse_nfa(
            transList,
            sindex,
            static_cast<unsigned char>(*T)
#ifdef AHO_CORASICK_SEARCH_STATS
            , &search_stats_
#endif
            );
#endif

        /* Log matches in this state - if any */
#ifdef AHO_CORASICK_SEARCH_STATS
        ++search_stats_.match_state_checks;
#endif
        if (sindex && isMatchState(transList[sindex + 1]) )
        {
#ifdef AHO_CORASICK_SEARCH_STATS
            ++search_stats_.match_state_hits;
#endif
            /* Test for same as last state */
            if (sindex == last_sindex)
                continue;

            mlist = MatchList[getCurrentState(transList[sindex])];
            while (mlist)
            {
                int index;
                bnfa_pattern_t* patrn = mlist->data;
                int offset = (T - begin);
                int raw_index = offset - static_cast<int>(patrn->n) + 1;
                if (raw_index < 0 && !patrn->nocase)
                {
                    mlist = mlist->next;
                    continue;
                }
                if (raw_index < 0)
                    index = 0;
                else
                    index = raw_index;
                nfound++;
#ifdef AHO_CORASICK_SEARCH_STATS
                ++search_stats_.match_candidates;
#endif
                if (_add_queue(mlist, index))
                {
                    if (_process_queue(match_functor, userdata,begin))
                    {
                        *current_state = sindex;
                        return 1;
                    }
                }
                mlist = mlist->next;
            }
        }
    }
    *current_state = sindex;

    return _process_queue(match_functor, userdata, begin);
}


/*
* Case specific search, global to all patterns
*/
template<typename RAIteratorUnderlying, typename RAIterator>
unsigned
AhoCorasickSearch::_bnfa_search_csparse_nfa_case(RAIterator begin, RAIterator Tend,
    match_function_functor_check<RAIteratorUnderlying> match_functor,
    any_t userdata, bnfa_state_index_t sindex, bnfa_state_index_t *current_state)
{
    bnfa_match_node_t  * mlist;
    RAIterator T = begin;
    bnfa_match_node_t ** MatchList = bnfaMatchList.data();
    bnfa_pattern_t     * patrn;
    bnfa_state_t       * transList = bnfaTransList.data();
#if AHO_CORASICK_FAILURELESS_CACHE_MAX_STATES > 0
    const size_t* failureless_cache_offsets = failureless_cache_offsets_.data();
    const bnfa_state_index_t* failureless_transition_cache = failureless_transition_cache_.data();
#endif
    unsigned             nfound = 0;
    bnfa_state_index_t             last_match = LAST_STATE_INIT;
    bnfa_state_index_t             last_match_saved = LAST_STATE_INIT;
    int                  res;

    for (; T<Tend; ++T)
    {
        /* Transition to next state index */
#if AHO_CORASICK_FAILURELESS_CACHE_MAX_STATES > 0
        sindex = _bnfa_get_next_state_failureless_nfa(
            transList,
            failureless_cache_offsets,
            failureless_transition_cache,
            sindex,
            static_cast<unsigned char>(*T)
#ifdef AHO_CORASICK_SEARCH_STATS
            , &search_stats_
#endif
            );
#else
        sindex = _bnfa_get_next_state_csparse_nfa(
            transList,
            sindex,
            static_cast<unsigned char>(*T)
#ifdef AHO_CORASICK_SEARCH_STATS
            , &search_stats_
#endif
            );
#endif

        /* Log matches in this state - if any */
#ifdef AHO_CORASICK_SEARCH_STATS
        ++search_stats_.match_state_checks;
#endif
        if (sindex && isMatchState(transList[sindex + 1]) )
        {
#ifdef AHO_CORASICK_SEARCH_STATS
            ++search_stats_.match_state_hits;
#endif
            if (sindex == last_match)
                continue;

            last_match_saved = last_match;
            last_match = sindex;
            mlist = MatchList[getCurrentState(transList[sindex])];
            while (mlist)
            {
                int index;
                patrn = mlist->data;
                int offset = static_cast<int>(T - begin);
                int raw_index = offset - static_cast<int>(patrn->n) + 1;
                bool starts_before_buffer = raw_index < 0;
                if (starts_before_buffer)
                    index = 0;
                else
                    index = raw_index;
                nfound++;
#ifdef AHO_CORASICK_SEARCH_STATS
                ++search_stats_.match_candidates;
#endif
                /* Don't do anything specific for case sensitive patterns and not,
                * since that will be covered by the rule tree itself.  Each tree
                * might have both case sensitive & case insensitive patterns.
                */
                res = match_functor(patrn->userdata, index, userdata, patrn, starts_before_buffer);
                if (res > 0)
                {
                    *current_state = sindex;
                    return nfound;
                }
                else if (res < 0)
                {
                    last_match = last_match_saved;
                }
                mlist = mlist->next;
            }
        }
    }
    *current_state = sindex;
    return nfound;
}

/*
*   Add a pattern to the pattern list
*/
template<typename RAIterator>
int
AhoCorasickSearch::addPattern(
    RAIterator patBegin, RAIterator patEnd, bool nocase,
    any_t userdata)
{
    if (patEnd <= patBegin || (patEnd - patBegin > UINT_MAX) )
        return -1;
    unsigned n = patEnd - patBegin;

    try
    {
        auto owned_pattern = std::make_unique<bnfa_pattern_t>();
        bnfa_pattern_t* plist = owned_pattern.get();
        plist->casepatrn.assign(patBegin, patEnd);
        plist->n = n;
        plist->nocase = nocase;
        plist->userdata = userdata;

        pattern_storage_.push_back(std::move(owned_pattern));

        plist->next = bnfaPatterns; /* insert at front of list */
        bnfaPatterns = plist;

        pat_memory += sizeof(bnfa_pattern_t) + plist->casepatrn.size() * sizeof(unsigned char);
        bnfaPatternCnt++;
    }
    catch (const std::bad_alloc&)
    {
        return -1;
    }

    return 0;
}

template <typename RAIteratorUnderlying,typename RAIterator>
unsigned
AhoCorasickSearch::_process_queue(match_function_functor_check<RAIteratorUnderlying> functor, any_t userdata, RAIterator begin)
{
    bnfa_match_node_t  * mlist;
    bnfa_pattern_t     * patrn;
    int                  res;

    for (match_queue_type::const_iterator it = match_queue.begin(), itEnd = match_queue.end(); it != itEnd; ++it)
    {
        mlist = it->data;
        if (mlist)
        {
            patrn = mlist->data;
            /*process a pattern -  case is handled by otn processing */
            res = functor(patrn->userdata, it->pos, userdata, patrn);
            if (res > 0)
            {    /* terminate matching */
                match_queue.clear();
                return 1;
            }
        }
    }
    match_queue.clear();
    return 0;
}

/*
*   Sparse format for state table using single array storage
*
*   word 1: state
*   word 2: control-word = cb<<24| fs
*       cb    : control-byte
*          : mb | fb | nt
*          mb : bit 8 set if match state, zero otherwise
*          fb : bit 7 set if using full format, zero otherwise
*          nt : number of transitions 0..63 (more than 63 requires full format)
*       fs: failure-transition-state
*   word 3+: byte-value(0-255) << 24 | transition-state
*/
// Performance hotspot
FORCE_INLINE
AhoCorasickSearch::bnfa_state_index_t
AhoCorasickSearch::_bnfa_get_next_state_csparse_nfa(
    bnfa_state_t * pcx,
    bnfa_state_index_t sindex,
    unsigned  input
#ifdef AHO_CORASICK_SEARCH_STATS
    , SearchStats* stats
#endif
    )
{
    unsigned k;
    unsigned int nc;
    int index;
    bnfa_state_t * pcs;

#ifdef AHO_CORASICK_SEARCH_STATS
    ++stats->transition_calls;
#endif

    for (;;)
    {
#ifdef AHO_CORASICK_SEARCH_STATS
        ++stats->state_visits;
#endif
        pcs = pcx + sindex + 1; /* skip state-id == 1st word */

        if (isFullFormat(pcs[0]))
        {
#ifdef AHO_CORASICK_SEARCH_STATS
            ++stats->full_row_visits;
#endif
#if AHO_CORASICK_FAILURELESS_FULL_ROWS
            bnfa_state_index_t idx = fullGetTransitionState(pcs[1 + input]);
            if (sindex == 0)
            {
#ifdef AHO_CORASICK_SEARCH_STATS
                ++stats->full_root_transitions;
                if (idx == 0)
                {
                    ++stats->full_root_zero_transitions;
                }
#endif
            }
            else
            {
#ifdef AHO_CORASICK_SEARCH_STATS
                ++stats->full_non_root_hits;
#endif
            }
            return idx;
#else
            if (sindex == 0)
            {
                bnfa_state_index_t idx = fullGetTransitionState(pcs[1 + input]);
#ifdef AHO_CORASICK_SEARCH_STATS
                ++stats->full_root_transitions;
                if (idx == 0)
                {
                    ++stats->full_root_zero_transitions;
                }
#endif
                return idx;
            }
            else
            {
                bnfa_state_index_t idx = fullGetTransitionState(pcs[1 + input]);
                if (idx != 0)
                {
#ifdef AHO_CORASICK_SEARCH_STATS
                    ++stats->full_non_root_hits;
#endif
                    return idx;
                }
#ifdef AHO_CORASICK_SEARCH_STATS
                ++stats->full_non_root_misses;
#endif
            }
#endif
        }
        else // Sparse
        {
#ifdef AHO_CORASICK_SEARCH_STATS
            ++stats->sparse_row_visits;
#endif
            nc = sparseGetNumberOfTransitions(pcs[0]);
            if (nc > BNFA_SPARSE_LINEAR_SEARCH_LIMIT)
            {
#ifdef AHO_CORASICK_SEARCH_STATS
                ++stats->sparse_binary_rows;
#endif
                /* binary search... */
                index = _bnfa_binearch(
                    pcs + 1,
                    nc,
                    input
#ifdef AHO_CORASICK_SEARCH_STATS
                    , stats
#endif
                    );
                if (index >= 0)
                {
#ifdef AHO_CORASICK_SEARCH_STATS
                    ++stats->sparse_binary_hits;
#endif
                    return sparseGetTransitionState(pcs[index + 1]);
                }
#ifdef AHO_CORASICK_SEARCH_STATS
                ++stats->sparse_binary_misses;
#endif
            }
            else
            {
#ifdef AHO_CORASICK_SEARCH_STATS
                ++stats->sparse_linear_rows;
#endif
                /* linear search... */
                for (k = 0; k < nc; k++)
                {
#ifdef AHO_CORASICK_SEARCH_STATS
                    ++stats->sparse_linear_comparisons;
#endif
                    if ((pcs[k + 1] >> BNFA_SPARSE_VALUE_SHIFT) == input)
                    {
#ifdef AHO_CORASICK_SEARCH_STATS
                        ++stats->sparse_linear_hits;
#endif
                        return sparseGetTransitionState(pcs[k + 1]);
                    }
                }
#ifdef AHO_CORASICK_SEARCH_STATS
                ++stats->sparse_linear_misses;
#endif
            }
        }

        /* no transition found ... get the failure state and try again  */
#ifdef AHO_CORASICK_SEARCH_STATS
        ++stats->failure_transitions;
#endif
        sindex = getFailureState(pcs[0]);
    }
}

FORCE_INLINE
AhoCorasickSearch::bnfa_state_index_t
AhoCorasickSearch::_bnfa_get_next_state_failureless_nfa(
    bnfa_state_t * pcx,
    const size_t* failureless_cache_offsets,
    const bnfa_state_index_t* failureless_transition_cache,
    bnfa_state_index_t sindex,
    unsigned input
#ifdef AHO_CORASICK_SEARCH_STATS
    , SearchStats* stats
#endif
    )
{
    const size_t cache_offset = failureless_cache_offsets[sindex];
    if (cache_offset != 0)
    {
#ifdef AHO_CORASICK_SEARCH_STATS
        ++stats->transition_calls;
        ++stats->state_visits;
        ++stats->failureless_cache_hits;
#endif
        return failureless_transition_cache[cache_offset - 1 + input];
    }

#ifdef AHO_CORASICK_SEARCH_STATS
    ++stats->failureless_cache_misses;
#endif
    return _bnfa_get_next_state_csparse_nfa(
        pcx,
        sindex,
        input
#ifdef AHO_CORASICK_SEARCH_STATS
        , stats
#endif
        );
}

}
#endif
