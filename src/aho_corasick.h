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

namespace textsearch {


/**
 * @brief Sparse NFA based Aho-Corasick multi-pattern search engine.
 *
 * Add all patterns, compile the automaton, then search one or more buffers.
 * The class is not copyable. It owns the compiled automaton and releases all
 * allocated storage in the destructor.
 */
class AhoCorasickSearch {
public:
    /// Type-erased data passed through pattern registration and search callbacks.
    using any_t = std::any;

    /**
     * @brief Match callback signature.
     *
     * @param pattern_userdata Userdata supplied when the matching pattern was added.
     * @param index Zero-based start offset of the match in the current search buffer.
     * @param search_userdata Userdata supplied to search().
     * @return Return a positive value to stop searching early; return 0 to continue.
     */
    typedef int(*match_function_ptr_t)(any_t pattern_userdata, int index, any_t search_userdata);
#ifdef BNFA_STATE_64BITS
    /// Packed automaton storage word.
    typedef uint64_t bnfa_state_t;
    /// Index into the packed automaton state storage.
    typedef uint_least64_t  bnfa_state_index_t;
#else
    /// Packed automaton storage word.
    typedef uint32_t bnfa_state_t;
    /// Index into the packed automaton state storage.
    typedef uint_least32_t bnfa_state_index_t;
#endif
    /// Controls how pattern and input case are handled.
    enum class bnfa_case : int {
        BNFA_PER_PAT_CASE, ///< Case sensitivity is specified per pattern.
        BNFA_CASE,         ///< Case-sensitive binary matching.
        BNFA_NOCASE        ///< Case-insensitive matching for all patterns.
    };

    /**
     * @brief Set the case handling mode.
     *
     * Set this before adding patterns and compiling the automaton. Changing the
     * case mode after compile() is not supported.
     */
    void setCase(bnfa_case flag);

    /// Create an empty search engine using the requested case mode.
    explicit AhoCorasickSearch(bnfa_case flag = bnfa_case::BNFA_CASE);

    /// Release all pattern and automaton storage.
    ~AhoCorasickSearch();
    
    /**
     * @brief Enable or disable failure-state optimization during compile().
     *
     * This must be configured before compile().
     */
    void setOptimizeFailureStates(bool flag=true);

    /**
     * @brief Add a pattern to the automaton input set.
     *
     * Patterns must be added before compile(). Empty patterns and patterns
     * larger than UINT_MAX bytes are rejected.
     *
     * @tparam RAIterator Random-access iterator over char-compatible bytes.
     * @param patBegin First pattern byte.
     * @param patEnd One-past-the-end pattern byte.
     * @param nocase In BNFA_PER_PAT_CASE mode, true makes this pattern
     * case-insensitive. In BNFA_CASE and BNFA_NOCASE modes this value is
     * ignored.
     * @param userdata User data passed back to the match callback.
     * @return 0 on success, -1 on invalid input or allocation failure.
     */
    template<typename RAIterator>
    int addPattern(
        RAIterator patBegin,
        RAIterator patEnd,
        bool nocase,
        any_t userdata
        );

    /**
     * @brief Build the searchable automaton from the added patterns.
     *
     * @return 0 on success, -1 on allocation failure or unsupported automaton
     * size/format.
     */
    int compile();

    /**
     * @brief Search a buffer and report matches through a callback.
     *
     * current_state is optional for single-buffer searches. Pass the same
     * non-null state pointer across calls to continue matching across buffers.
     * In BNFA_PER_PAT_CASE, case-sensitive patterns that begin before the
     * current buffer cannot be exact-case verified and are not reported.
     *
     * @tparam RAIterator Random-access iterator over char-compatible bytes.
     * @param begin First input byte.
     * @param end One-past-the-end input byte.
     * @param match Callback invoked for each reported match.
     * @param userdata User data passed to the callback as search_userdata.
     * @param sindex Initial automaton state for legacy callers. Use 0 for new
     * searches.
     * @param current_state Optional state pointer for streaming searches. If
     * non-null, its input value overrides sindex and its output value can be
     * passed to the next search() call.
     * @return Legacy status/count value. Use the callback as the authoritative
     * match-reporting mechanism.
     */
    template<typename RAIterator>
    unsigned search(RAIterator begin, RAIterator end,
        match_function_ptr_t match,
        any_t userdata,
        bnfa_state_index_t sindex,
        bnfa_state_index_t* current_state);

    /// Return the number of patterns added to this search engine.
    int getPatternCount();

    /// Print the compiled NFA states to stderr. Intended for diagnostics.
    void print();
    /// Print memory and state statistics to stderr.
    void printInfo();
    /// Print memory and state statistics to stderr with a legacy text argument.
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
    int                bnfaForceFullZeroState;

    std::vector<std::unique_ptr<bnfa_pattern_t>> pattern_storage_;
    std::vector<std::unique_ptr<bnfa_trans_node_t>> transition_node_storage_;
    std::vector<std::unique_ptr<bnfa_match_node_t>> match_node_storage_;

    size_t 			   bnfa_memory;
    size_t 			   pat_memory;
    size_t 			   list_memory;
    size_t 			   nextstate_memory;
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
    
    static FORCE_INLINE bnfa_state_index_t _bnfa_get_next_state_csparse_nfa(bnfa_state_t * pcx, bnfa_state_index_t sindex, unsigned  input);


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

    static inline int _bnfa_binearch(bnfa_state_t * a, int a_len, bnfa_state_t val)
    {
        int m, l, r;
        bnfa_state_t c;
        l = 0;
        r = a_len - 1;
        while (r >= l)
        {
            m = (r + l) >> 1;
            c = a[m] >> BNFA_SPARSE_VALUE_SHIFT;
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
    bnfa_state_index_t   last_sindex;
    unsigned int nfound = 0;

    _init_queue();

    for (; T<Tend; ++T)
    {
        last_sindex = sindex;

        /* Transition to next state index */
        sindex = _bnfa_get_next_state_csparse_nfa(transList, sindex, static_cast<unsigned char>(*T));

        /* Log matches in this state - if any */
        if (sindex && isMatchState(transList[sindex + 1]) )
        {
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
    unsigned             nfound = 0;
    bnfa_state_index_t             last_match = LAST_STATE_INIT;
    bnfa_state_index_t             last_match_saved = LAST_STATE_INIT;
    int                  res;

    for (; T<Tend; ++T)
    {
        /* Transition to next state index */
        sindex = _bnfa_get_next_state_csparse_nfa(transList, sindex, static_cast<unsigned char>(*T));

        /* Log matches in this state - if any */
        if (sindex && isMatchState(transList[sindex + 1]) )
        {
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
    )
{
    unsigned k;
    unsigned int nc;
    int index;
    bnfa_state_t * pcs;

    for (;;)
    {
        pcs = pcx + sindex + 1; /* skip state-id == 1st word */

        if (isFullFormat(pcs[0]))
        {
            if (sindex == 0)
            {
                return fullGetTransitionState(pcs[1 + input]);
            }
            else
            {
                bnfa_state_index_t idx = fullGetTransitionState(pcs[1 + input]);
                if (idx != 0)
                    return idx;
            }
        }
        else // Sparse
        {
            nc = sparseGetNumberOfTransitions(pcs[0]);
            if (nc > BNFA_SPARSE_LINEAR_SEARCH_LIMIT)
            {
                /* binary search... */
                index = _bnfa_binearch(pcs + 1, nc, input);
                if (index >= 0)
                {
                    return sparseGetTransitionState(pcs[index + 1]);
                }
            }
            else
            {
                /* linear search... */
                for (k = 0; k < nc; k++)
                {
                    if ((pcs[k + 1] >> BNFA_SPARSE_VALUE_SHIFT) == input)
                    {
                        return sparseGetTransitionState(pcs[k + 1]);
                    }
                }
            }
        }

        /* no transition found ... get the failure state and try again  */
        sindex = getFailureState(pcs[0]);
    }
}

}
#endif
