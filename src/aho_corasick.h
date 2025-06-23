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
#include <set>
#include <algorithm>
#include <any>


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
    
    template<typename RAIterator>
    unsigned search(RAIterator begin, RAIterator end,
        match_function_ptr_t match,
        any_t userdata,
        bnfa_state_index_t sindex,
        bnfa_state_index_t* current_state);

    int getPatternCount();

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

    static const bnfa_state_t BNFA_SPARSE_MAX_STATE = 0x00ffffffffffffff;
    static const unsigned BNFA_SPARSE_COUNT_SHIFT = 56;
    static const unsigned BNFA_SPARSE_VALUE_SHIFT = 56;

    static const bnfa_state_t BNFA_SPARSE_MATCH_BIT = 0x8000000000000000;
    static const bnfa_state_t BNFA_SPARSE_FULL_BIT = 0x4000000000000000;
    static const bnfa_state_t BNFA_SPARSE_COUNT_BITS = 0x3f00000000000000;
    static const unsigned BNFA_SPARSE_MAX_ROW_TRANSITIONS = 0x3f;
    static const bnfa_state_t BNFA_SPARSE_CONTROL_BITS = 0xff00000000000000; // control Word
    static const bnfa_state_t BNFA_SPARSE_CHAR_BITS = 0xff00000000000000; // next words
    /*
    * Used to initialize last state, states are limited to 56 bits
    * so this will not conflict.
    */
    static const bnfa_state_t LAST_STATE_INIT = 0xffffffffffffffff;
    static const bnfa_state_t BNFA_FAIL_STATE = 0xffffffffffffffff;

#else

    static const bnfa_state_index_t BNFA_SPARSE_MAX_STATE = 0x00ffffff;
    static const unsigned BNFA_SPARSE_COUNT_SHIFT = 24;
    static const unsigned BNFA_SPARSE_VALUE_SHIFT = 24;

    static const bnfa_state_index_t BNFA_SPARSE_MATCH_BIT = 0x80000000;
    static const bnfa_state_index_t BNFA_SPARSE_FULL_BIT = 0x40000000;
    static const bnfa_state_index_t BNFA_SPARSE_COUNT_BITS = 0x3f000000;
    static const unsigned BNFA_SPARSE_MAX_ROW_TRANSITIONS = 0x3f;
    static const bnfa_state_index_t BNFA_SPARSE_CONTROL_BITS = 0xff000000; // control Word
    static const bnfa_state_index_t BNFA_SPARSE_CHAR_BITS = 0xff000000; // next words
    /*
    * Used to initialize last state, states are limited to 0-16M
    * so this will not conflict.
    */
    static const bnfa_state_index_t LAST_STATE_INIT = 0xffffffff;
    static const bnfa_state_t BNFA_FAIL_STATE      = 0xffffffff;

#endif

    static const unsigned BNFA_SPARSE_LINEAR_SEARCH_LIMIT = 6;
    static const unsigned BNFA_MAX_ALPHABET_SIZE = 256;

 
    /*
    *   Internal Pattern Representation
    */

    typedef struct bnfa_pattern	{
        struct bnfa_pattern * next;

        unsigned char       * casepatrn;   /* case specific */
        unsigned              n;           /* pattern len */
        bool                  nocase;      /* nocase flag */
        any_t userdata;    /* ptr to users pattern data/info  */

    } bnfa_pattern_t;

    /*
    *  List format transition node
    */
    typedef struct bnfa_trans_node_s {
        unsigned int               key; // 8 bit character
        bnfa_state_index_t         next_state;
        struct bnfa_trans_node_s * next;

    } bnfa_trans_node_t;

    /*
    *  List format patterns
    */
    typedef struct bnfa_match_node_s {
        bnfa_pattern_t* data;
        struct bnfa_match_node_s * next;

    } bnfa_match_node_t;

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
            bool check=false
            ) : userfunc_(userfunc), begin_(begin),check_(check) {}
        int operator() (
            any_t pattern_userdata, 
            int index, 
            any_t search_userdata, 
            bnfa_pattern_t* pattern
            )
        {
            if (check_ && !pattern->nocase)
            {
                if (std::equal(
                        pattern->casepatrn,
                        pattern->casepatrn+pattern->n,
                        begin_ +index
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

    typedef struct bnfa_trans_table {
        bnfa_state_t* states;
        bnfa_trans_node_t* transitions[]; // transitions[0] was states in union
    } bnfa_trans_table_t;

    bnfa_trans_table_t  * bnfaTransTable;

    bnfa_state_t       ** bnfaNextState;
    bnfa_match_node_t  ** bnfaMatchList;
    bnfa_state_index_t       * bnfaFailState;

    bnfa_state_t       * bnfaTransList;
    int                bnfaForceFullZeroState;

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
    template <typename T>
    static T* bnfa_alloc(size_t n, size_t& m, T*);
    template <typename T>
    static T* bnfa_alloc(size_t& m, T*);
    template <typename T>
    static void bnfa_free(T* p, size_t n, size_t& m);
    template <typename T>
    static void bnfa_free(T* p, size_t& m);


};

template<typename RAIterator>
unsigned
AhoCorasickSearch::search(RAIterator begin, RAIterator end,
    match_function_ptr_t Match,
    any_t userdata, bnfa_state_index_t sindex, bnfa_state_index_t* current_state)
{
    int ret = 0;

    if (current_state)
    {
        sindex = *current_state;
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
                match_function_functor_check<RAIterator>(Match,begin,true),
                userdata, 
                sindex, 
                current_state
                );
        }
        else
        {
            ret = _bnfa_search_csparse_nfa_q(
                itBegin, 
                itEnd, 
                match_function_functor_check<RAIterator>(Match,begin, true),
                userdata,
                sindex, 
                current_state
                );
        }
    }
    else if (bnfaCaseMode == bnfa_case::BNFA_CASE)
    {
        ret = _bnfa_search_csparse_nfa_case(
            begin, 
            end, 
            match_function_functor_check<RAIterator>(Match, begin,false),
            userdata, 
            sindex, 
            current_state
            );
    }
    else/* NOCASE */
    {
        functor_iterator<character_functor, RAIterator> itBegin(toupper_functor, begin);
        functor_iterator<character_functor, RAIterator> itEnd(toupper_functor, end);
        ret = _bnfa_search_csparse_nfa_case(
            itBegin, 
            itEnd, 
            match_function_functor_check<RAIterator>(Match, begin, false),
            userdata, 
            sindex, 
            current_state
            );
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

    bnfa_match_node_t ** MatchList = bnfaMatchList;
    bnfa_state_t       * transList = bnfaTransList;
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
            if (mlist)
            {
                int index;
                bnfa_pattern_t* patrn = mlist->data;
                int offset = (T - begin);
                if ( offset < patrn->n)
                    index = 0;
                else
                    index = offset - patrn->n + 1;
                nfound++;
                if (_add_queue(mlist, index))
                {
                    if (_process_queue(match_functor, userdata,begin))
                    {
                        *current_state = sindex;
                        return 1;
                    }
                }
            }
        }
    }
    *current_state = sindex;

    return _process_queue(match_functor, userdata, begin);
}


/*
* Custom memory allocator
*/
template <typename T>
/*static*/ 
T* AhoCorasickSearch::bnfa_alloc(size_t n, size_t& m, T*)
{
    T* p;
    if (n > 1)
        p = new (std::nothrow) T[n]();
    else
        p = new (std::nothrow) T();
    if (p)
    {
        m += n *sizeof(T);
    }
    return p;
}

template <typename T>
/*static*/ 
T* AhoCorasickSearch::bnfa_alloc(size_t& m, T*)
{
    T* p = new (std::nothrow) T();
    if (p)
    {
        m += sizeof(T);
    }
    return p;
}

template <typename T>
/*static*/ 
void AhoCorasickSearch::bnfa_free(T* p, size_t n, size_t& m)
{
    if (p)
    {
        if (n > 1)
            delete[] p;
        else
            delete p;
        m -= n * sizeof(T);
    }
}
template <typename T>
/*static*/
void AhoCorasickSearch::bnfa_free(T* p, size_t& m)
{
    if (p)
    {
        delete p;
        m -= sizeof(T);
    }
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
    bnfa_match_node_t ** MatchList = bnfaMatchList;
    bnfa_pattern_t     * patrn;
    bnfa_state_t       * transList = bnfaTransList;
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
            if(mlist)
            {
                int index;
                patrn = mlist->data;
                int offset = static_cast<int>(T - begin);
                if (offset < patrn->n)
                    index = 0;
                else
                    index = offset - patrn->n + 1;
                nfound++;
                /* Don't do anything specific for case sensitive patterns and not,
                * since that will be covered by the rule tree itself.  Each tree
                * might have both case sensitive & case insensitive patterns.
                */
                res = match_functor(patrn->userdata, index, userdata,patrn);
                if (res > 0)
                {
                    *current_state = sindex;
                    return nfound;
                }
                else if (res < 0)
                {
                    last_match = last_match_saved;
                }
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
    bnfa_pattern_t * plist;
    if (patEnd <= patBegin || (patEnd - patBegin > UINT_MAX) )
        return -1;
    unsigned n = patEnd - patBegin;

    plist = bnfa_alloc(1, pat_memory, (bnfa_pattern_t*)0); //NOLINT
    if (!plist) return -1;

    plist->casepatrn = bnfa_alloc(n, pat_memory, (unsigned char *)0); //NOLINT
    if (!plist->casepatrn)
    {
        bnfa_free(plist, pat_memory);
        return -1;
    }

    std::copy(patBegin, patEnd, plist->casepatrn);

    plist->n = n;
    plist->nocase = nocase;
    plist->userdata = userdata;

    plist->next = bnfaPatterns; /* insert at front of list */
    bnfaPatterns = plist;

    bnfaPatternCnt++;

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
            res = functor(patrn->userdata, it->pos, userdata,patrn);
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
