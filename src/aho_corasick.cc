/*
** aho_corasick.cc
**
** Multi-pattern search engine using Aho-Corasick NFA construction.
**
** Version 4.0: port to C++ and enhance (based on snort bnfa_search.c)
** author: christophe pierret
** date: started 19/03/2016
** Copyright 2016 Christophe Pierret. All rights reserved.
**
** author: marc norton
** date:   started 12/21/05
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2005-2013 Sourcefire, Inc.
**
** General Design
**  Aho-Corasick based NFA state machine.
**  Compacted sparse storage mode for better performance.
**  Up to 16 Million states + transitions (combined) in compacted sparse mode.
**
**  ** Compacted sparse array storage **
**
**  The primary data is held in one array.
**  The patterns themselves are stored separately.
**  The matching lists of patterns for each state are stored separately as well.
**  The compacted sparse format improves caching/performance.
**
**   word 1 : state  ( only low 24 bits are used )
**   word 2 : control word = cb << 24 | fs
**   cb: control byte
**       cb = mb | fb | nt
**   mb : 8th bit - if set state has matching patterns bit
**   fb : 7th bit - if set full storage array bit (256 entries used),
                    else sparse
**   nt : 0-63= number of transitions (more than 63 requires full storage)
**   fs: 24 bits for failure state transition index.
**   word 3+ : transition word =  input<<24 |  next-state-index
**   input : 8 bit character, input to state machine from search text
**   next-state-index: 24 bits for index of next state
**     (if we reallly need 16M states, we can add a state->index lookup array)
**     ...repeat for each state ...
**
**   * if a state is empty it has words 1 and 2, but no transition words.
**
**   Construction:
**
**   Patterns are added to a list based trie.
**   The list based trie is compiled into a list based NFA with failure states.
**   The list based NFA is converted to full or sparse format NFA.
**   The Zero'th state sparse transitions may be stored in full format for
**      performance.
**   Sparse transition arrays are searched using linear and binary search
**      strategies depending on the number of entries to search through in
**      each state.
**   The state machine in sparse mode is compacted into a single vector for
**      better performance.
**
** Notes:
**
** The NFA can require twice the state transitions that a DFA uses. However,
** the construction of a DFA generates many additional transitions in each
** state which consumes significant additional memory. This particular
** implementation is best suited to environments where the very large memory
** requirements of a full state table implementation is not possible and/or
** the speed trade off is warranted to maintain a small memory footprint.
**
** Each state of an NFA usually has very few transitions but can have up to
** 256.  It is important to not degenerate into a linear search so we utilize
** a binary search if there are more than 5 elements in the state to test for
** a match.  This allows us to use a simple sparse memory design with an
** acceptable worst case search scenario.  The binary search over 256 elements
** is limtied to a max of 8 tests.  The zero'th state may use a full 256 state
** array, so a quick index lookup provides the next state transition.  The
** zero'th state is generally visited much more than other states.
**
** Compiling : gcc, Intel C/C++, Microsoft C/C++, each optimize differently.
** My studies have shown Intel C/C++ 9,8,7 to be the fastest, Microsoft 8,7,6
** is next fastest, and gcc 4.x,3.x,2.x is the slowest of the three.  My
** testing has been mainly on x86.  In general gcc does a poor job with
** optimizing this state machine for performance, compared to other less cache
** and prefetch sensitive algorithms.  I've documented this behavior in a
** paper 'Optimizing Pattern Matching for IDS' (www.sourcefire.com,
** www.idsresearch.org).
**
** The code is sensitive to cache optimization and prefetching, as well as
** instruction pipelining.  Aren't we all.  To this end, the number of
** patterns, length of search text, and cpu cache L1,L2,L3 all affect
** performance. The relative performance of the sparse and full format NFA and
** DFA varies as you vary the pattern characteristics,and search text length,
** but strong performance trends are present and stable.
**
**
**  BNFA API SUMMARY
**
**  bnfa=bnfaNew();             create a state machine
**  bnfaAddPattern(bnfa,..);    add a pattern to the state machine
**  bnfaCompile (bnfa,..)       compile the state machine
**  bnfaPrintInfo(bnfa);        print memory usage and state info
**  bnfaPrint(bnfa);            print the state machine in total
**  state=bnfaSearch(bnfa, ...,state);  search a data buffer for a pattern match
**  bnfaFree (bnfa);            free the bnfa
**
**
** Reference - Efficient String matching: An Aid to Bibliographic Search
**             Alfred V Aho and Margaret J Corasick
**             Bell Labratories
**             Copyright(C) 1975 Association for Computing Machinery,Inc
**
** 12/4/06 - man - modified summary
** 6/26/07 - man - Added last_match tracking, and accounted for nocase/case by
**                 preseting the last match state, and reverting if we fail the
**                 case memcmp test for any rule in the states matching rule
**                 list.  The states in the defaul matcher represent either
**                 case or nocase states, so they are dual mode, that makes
**                 this a bit tricky.  When we sue the pure exact match, or
**                 pure don't care matching routines, we just track the last
**                 state, and never need to revert.  This only tracks the
**                 single repeated states and repeated data.
** 01/2008 - man - added 2 phase pattern matcher using a pattern match queue.
**                 Text is scanned and matching states are queued, duplicate
**                 matches are dropped, and after the complete buffer scan the
**                 queued matches are processed.  This improves cacheing
**                 performance, and reduces duplicate rule processing.  The
**                 queue is limited in size and is flushed if it becomes full
**                 during the scan.  This allows simple insertions.  Tracking
**                 queue ops is optional, as this can impose a modest
**                 performance hit of a few percent.
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
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
*/
#include "aho_corasick.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <cstddef>

#include <deque>

namespace textsearch {

void LogMessage(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}


/*
*  Get next state from transition list
*/
AhoCorasickSearch::bnfa_state_index_t
AhoCorasickSearch::_bnfa_list_get_next_state(bnfa_state_index_t state, unsigned char input) {

    if (state == 0) { /* Full (format) set of states  always */
        if (bnfaTransTable->states.empty()) {
            return 0;
        }
        return fullGetTransitionState(bnfaTransTable->states[input]);
    } else {
        bnfa_trans_node_t* t = bnfaTransTable->transitions[state];
        while (t) {
            if (t->key == input) {
                return t->next_state;
            }
            t = t->next;
        }
        return BNFA_FAIL_STATE; /* Fail state */
    }
}

/*
*  Put next state - head insertion, and transition updates
*/
int
AhoCorasickSearch::_bnfa_list_put_next_state(
    bnfa_state_index_t state,
    unsigned char input,
    bnfa_state_index_t next_state) {

    if (state >= bnfaMaxStates) {
        return -1;
    }

    if (input >= bnfaAlphabetSize) {
        return -1;
    }

    if (state == 0) {
        if (bnfaTransTable->states.empty()) {
            bnfaTransTable->states.assign(bnfaAlphabetSize, 0);
            list_memory += bnfaTransTable->states.size() * sizeof(bnfa_state_t);
        }
        if (bnfaTransTable->states[input]!=0) {
            bnfaTransTable->states[input] = next_state;
            return 0;
        }
        bnfaTransTable->states[input] = next_state;
    } else {
        bnfa_trans_node_t * p;
        bnfa_trans_node_t * tnew;

        /*
        ** Check if the transition already exists,
        ** if so just update the next_state
        */
        p = bnfaTransTable->transitions[state];
        while (p) {
            if (p->key == static_cast<unsigned>(input)) {
                /* transition already exists- reset the next state */
                p->next_state = next_state;
                return 0;
            }
            p = p->next;
        }

        /* Definitely not an existing transition - add it */
        tnew = _make_transition_node();

        tnew->key = input;
        tnew->next_state = next_state;
        tnew->next = bnfaTransTable->transitions[state];

        bnfaTransTable->transitions[state] = tnew;
    }

    bnfaNumTrans++;

    return 0;
}

/*
*   Free the entire transition list table
*/
int AhoCorasickSearch::_bnfa_list_free_table() {
    std::vector<std::unique_ptr<bnfa_trans_node_t>>().swap(transition_node_storage_);
    bnfaTransTable.reset();
    list_memory = 0;

    return 0;
}


/*
* Converts a single row of states from list format to a full format
*/
ptrdiff_t
AhoCorasickSearch::_bnfa_list_conv_row_to_full(
    bnfa_state_index_t state,
    bnfa_state_t * full ) {

    if (state >= bnfaMaxStates) {
        /* protects 'full' against overflow */
        return -1;
    }

    if (state == 0) {
        if (!bnfaTransTable->states.empty()) {
            memcpy(
            full,
            bnfaTransTable->states.data(),
            sizeof(bnfa_state_t)*bnfaAlphabetSize);
        } else {
            memset(full, 0, sizeof(bnfa_state_t)*bnfaAlphabetSize);
        }
        return static_cast<ptrdiff_t>(bnfaAlphabetSize);
    } else {
        int tcnt = 0;

        bnfa_trans_node_t * t = bnfaTransTable->transitions[state];

        memset(full, 0, sizeof(bnfa_state_t)*bnfaAlphabetSize);

        if (!t) 
            return 0;


        while (t && (t->key < BNFA_MAX_ALPHABET_SIZE)) {
            full[t->key] = t->next_state;
            tcnt++;
            t = t->next;
        }
        return static_cast<ptrdiff_t>(tcnt);
    }
}

/*
*  Add pattern characters to the initial upper case trie
*  unless Exact has been specified, in  which case all patterns
*  are assumed to be case specific.
*/

int
AhoCorasickSearch::_bnfa_add_pattern_states(bnfa_pattern_t * p) {
    bnfa_state_index_t state, next;
    size_t  n;
    const unsigned char * pattern;
    bnfa_match_node_t  * pmn;
    n = p->n;
    pattern = p->casepatrn.data();
    state = 0;

    /*
    *  Match up pattern with existing states
    */
    for (; n > 0; pattern++, n--) {
        if (bnfaCaseMode == bnfa_case::BNFA_CASE)
            next = _bnfa_list_get_next_state(state, *pattern);
        else
            next = _bnfa_list_get_next_state(state, toupper_functor(*pattern));

        if (next == BNFA_FAIL_STATE || next == 0)
            break;

        state = next;
    }

    /*
    **   Add new states for the rest of the pattern bytes,
    **   1 state per byte, uppercase
    */
    for (; n > 0; pattern++, n--)
    {
        bnfaNumStates++;

        if (bnfaCaseMode == bnfa_case::BNFA_CASE)
        {
            if (_bnfa_list_put_next_state(state, *pattern, bnfaNumStates) < 0)
                return -1;
        }
        else
        {
            if (_bnfa_list_put_next_state(
                state,
                toupper_functor(*pattern),
                bnfaNumStates) < 0
                )
                return -1;
        }
        state = bnfaNumStates;

        if (bnfaNumStates >= bnfaMaxStates)
        {
            return -1;
        }
    }

    /*  Add a pattern to the list of patterns terminated at this state */
    pmn = _make_match_node();

    pmn->data = p;
    pmn->next = bnfaMatchList[state];

    bnfaMatchList[state] = pmn;

    return 0;
}

/* used only by KcontainsJ() */
size_t
AhoCorasickSearch::_bnfa_conv_node_to_full(
    bnfa_trans_node_t* t,
    bnfa_state_t * full
    )
{
    int tcnt = 0;

    memset(full, 0, sizeof(bnfa_state_t)*BNFA_MAX_ALPHABET_SIZE);

    if (!t)
    {
        return 0;
    }

    while (t && (t->key < BNFA_MAX_ALPHABET_SIZE))
    {
        full[t->key] = t->next_state;
        tcnt++;
        t = t->next;
    }
    return tcnt;
}

int
AhoCorasickSearch::KcontainsJ(bnfa_trans_node_t* tk, bnfa_trans_node_t* tj)
{
    bnfa_state_t       full[BNFA_MAX_ALPHABET_SIZE];

    if (!_bnfa_conv_node_to_full(tk, full))
        return 1; /* emtpy state */

    while (tj)
    {
        if (!full[tj->key])
            return 0;

        tj = tj->next; /* get next tj key */
    }
    return 1;
}

/*
 * 1st optimization - eliminate duplicate fail states
 *
 * check if a fail state is a subset of the current state,
 * if so recurse to the next fail state, and so on.
 */
int AhoCorasickSearch::_bnfa_opt_nfa()
{
    int            cnt = 0;
    unsigned            k;
    bnfa_state_index_t fs, fr;
    bnfa_state_index_t * FailState = bnfaFailState.data();

    for (k = 2; k < bnfaNumStates; k++)
    {
        fr = fs = FailState[k];
        while ((fs!=0) &&  KcontainsJ(bnfaTransTable->transitions[k], bnfaTransTable->transitions[fs]))
        {
            fs = FailState[fs];
        }
        if (fr != fs)
        {
            cnt++;
            FailState[k] = fs;
        }
    }
    return 0;
}

/*
*   Build a non-deterministic finite automata using Aho-Corasick construction
*   The keyword trie must already be built via _bnfa_add_pattern_states()
*/
int
AhoCorasickSearch::_bnfa_build_nfa()
{
    bnfa_state_index_t r,s;
    std::deque< bnfa_state_index_t > queue;
    bnfa_state_index_t     * FailState = bnfaFailState.data();
    bnfa_match_node_t ** MatchList = bnfaMatchList.data();
    bnfa_match_node_t  * mlist;
    bnfa_match_node_t  * px;

    /* Add the state 0 transitions 1st,
    * the states at depth 1, fail to state 0
    */
    for (unsigned i = 0; i < bnfaAlphabetSize; i++)
    {
        /* note that state zero does not fail,
        *  it just returns 0..nstates-1
        */
        s = _bnfa_list_get_next_state(0, i);
        if (s!=0) /* don't bother adding state zero */
        {
            queue.push_back(s);
            FailState[s] = 0;
        }
    }

    /* Build the fail state successive layer of transitions */
    while (!queue.empty())
    {
        r = queue.front();
        queue.pop_front();

        /* Find Final States for any Failure */
        for (unsigned i = 0; i < bnfaAlphabetSize; i++)
        {
            bnfa_state_index_t fs, next;

            s = _bnfa_list_get_next_state(r, i);

            if (s == BNFA_FAIL_STATE)
                continue;

            queue.push_back(s);

            fs = FailState[r];

            /*
            *  Locate the next valid state for 'i' starting at fs
            */
            while (
                (next = _bnfa_list_get_next_state(fs, i))
                == BNFA_FAIL_STATE
                )
            {
                fs = FailState[fs];
            }

            /*
            *  Update 's' state failure state to point to the next valid state
            */
            FailState[s] = next;

            /*
            *  Copy 'next'states MatchList into 's' states MatchList,
            *  we just create a new list nodes, the patterns are not copied.
            */
            for (mlist = MatchList[next]; mlist; mlist = mlist->next)
            {
                /* Dup the node, don't copy the data */
                px = _make_match_node();

                px->data = mlist->data;

                px->next = MatchList[s]; /* insert at head */

                MatchList[s] = px;
            }
        }
    }

    /* optimize the failure states */
    if (bnfaOptimizeFailureStates)
        _bnfa_opt_nfa();

    return 0;
}


/*
*  Convert state machine to csparse format
*
*  Merges state/transition/failure arrays into one.
*
*  For each state we use a state-word followed by the transition list for
*  the state sw(state 0 )...tl(state 0) sw(state 1)...tl(state1) sw(state2)...
*  tl(state2) ....
*
*  The transition and failure states are replaced with the start index of
*  transition state, this eliminates the NextState[] lookup....
*
*  The compaction of multiple arays into a single array reduces the total
*  number of states that can be handled since the max index is 2^24-1,
*  whereas without compaction we had 2^24-1 states.
*/
int
AhoCorasickSearch::_bnfa_conv_list_to_csparse_array()
{
    unsigned            i;
    unsigned nc;
    bnfa_state_index_t      state;
    bnfa_state_index_t    * FailState = bnfaFailState.data();
    bnfa_state_t    * ps; /* transition list */
    bnfa_state_index_t    * pi; /* state indexes into ps */
    unsigned int      ps_index = 0;
    bnfa_state_index_t       nps;
    bnfa_state_t      full[BNFA_MAX_ALPHABET_SIZE];


    /* count total state transitions, account for state and control words  */
    nps = 0;
    for (bnfa_state_index_t k = 0; k < bnfaNumStates; k++)
    {
        nps++; /* state word */
        nps++; /* control word */

        /* count transitions */
        nc = 0;
        if (_bnfa_list_conv_row_to_full(k, full) < 0)
        {
            return -1;
        }
        for (i = 0; i<bnfaAlphabetSize; i++)
        {
            state = fullGetTransitionState(full[i]);
            if (state != 0)
            {
                nc++;
            }
        }

        /* add in transition count */
        if ((k == 0 && bnfaForceFullZeroState)
            || nc > BNFA_SPARSE_MAX_ROW_TRANSITIONS
            )
        {
            nps += BNFA_MAX_ALPHABET_SIZE;
        }
        else
        {
            for (i = 0; i < bnfaAlphabetSize; i++)
            {
                state = fullGetTransitionState(full[i]);
                if (state != 0)
                {
                    nps++;
                }
            }
        }
    }

    /* check if we have too many states + transitions */
    if (nps > BNFA_SPARSE_MAX_STATE)
    {
        /* Fatal */
        return -1;
    }

    std::vector<bnfa_state_t> transition_list(nps);
    ps = transition_list.data();

    std::vector<bnfa_state_index_t> state_indexes(bnfaNumStates);
    pi = state_indexes.data();

    /*
        Build the Transition List Array
    */
    for (bnfa_state_index_t k = 0; k < bnfaNumStates; k++)
    {
        pi[k] = ps_index; /* save index of start of state 'k' */

        ps[ps_index] = k; /* save the state were in as the 1st word */

        ps_index++;  /* skip past state word */

        /* conver state 'k' to full format */
        if (_bnfa_list_conv_row_to_full(k, full) < 0)
        {
            return -1;
        }

        /* count transitions */
        nc = 0;
        for (i = 0; i<bnfaAlphabetSize; i++)
        {
            state = fullGetTransitionState(full[i]);
            if (state != 0)
            {
                nc++;
            }
        }

        /* add a full state or a sparse state  */
        if ((k == 0 && bnfaForceFullZeroState) ||
            nc > BNFA_SPARSE_MAX_ROW_TRANSITIONS)
        {
            // Full format
            /* set the control word */
            ps[ps_index] = BNFA_SPARSE_FULL_BIT;
            ps[ps_index] |= getFailureState(FailState[k]);
            if (bnfaMatchList[k])
            {
                ps[ps_index] |= BNFA_SPARSE_MATCH_BIT;
            }
            ps_index++;

            /* copy the transitions */
            if (_bnfa_list_conv_row_to_full(k, &ps[ps_index]) < 0)
            {
                return -1;
            }

            ps_index += BNFA_MAX_ALPHABET_SIZE;  /* add in 256 transitions */

        }
        else
        {
            // Sparse format
            /* set the control word */
            ps[ps_index] = static_cast<bnfa_state_t>(nc) << BNFA_SPARSE_COUNT_SHIFT;
            ps[ps_index] |= getFailureState(FailState[k]);
            if (bnfaMatchList[k])
            {
                ps[ps_index] |= BNFA_SPARSE_MATCH_BIT;
            }
            ps_index++;

            /* add in the transitions */
            for (unsigned m = 0, ch = 0; ch < bnfaAlphabetSize && m < nc; ch++)
            {
                state = fullGetTransitionState(full[ch]);
                if (state != 0)
                {
                    ps[ps_index++] = static_cast<bnfa_state_t>(ch) << BNFA_SPARSE_VALUE_SHIFT | state;
                    m++;
                }
            }
        }
    }

    /* sanity check we have not overflowed our buffer */
    if (ps_index > nps)
    {
        /* Fatal */
        return -1;
    }

    /*
    Replace Transition states with Transition Indices.
    This allows us to skip using NextState[] to locate the next state
    This limits us to <16M transitions due to 24 bit state sizes, and the fact
    we have now converted next-state fields to next-index fields in this array,
    and we have merged the next-state and state arrays.
    */
    ps_index = 0;
    for (unsigned k = 0; k < bnfaNumStates; k++)
    {
        if (pi[k] >= nps)
        {
            /* Fatal */
            return -1;
        }

        ps_index++;        /* skip state id */

        /* Full Format */
        if ( isFullFormat(ps[ps_index]) )
        {
            /* Do the fail-state */
            ps[ps_index] = makeControlState(ps[ps_index], pi[ getFailureState(ps[ps_index]) ] );
            ps_index++;

            /* Do the transition-states */
            for (i = 0; i < BNFA_MAX_ALPHABET_SIZE; i++)
            {
                ps[ps_index] = makeTransitionState(ps[ps_index],
                    pi[fullGetTransitionState(ps[ps_index])]);
                ps_index++;
            }
        }

        /* Sparse Format */
        else
        {
            nc = (ps[ps_index] & BNFA_SPARSE_COUNT_BITS)
                >> BNFA_SPARSE_COUNT_SHIFT;

            /* Do the cw = [cb | fail-state] */
            ps[ps_index] = makeControlState(ps[ps_index], pi[getFailureState(ps[ps_index])]);

            ps_index++;

            /* Do the transition-states */
            for (i = 0; i < nc; i++)
            {
                ps[ps_index] = makeTransitionState(ps[ps_index],
                    pi[sparseGetTransitionState(ps[ps_index])]);
                ps_index++;
            }
        }

        /* check for buffer overflow again */
        if (ps_index > nps)
        {
            /* Fatal */
            return -1;
        }

    }

    bnfaTransList = std::move(transition_list);
    nextstate_memory = bnfaTransList.size() * sizeof(bnfa_state_t);

    return 0;
}

/*
*  Print the state machine - rather verbose
*/
void AhoCorasickSearch::print()
{
    unsigned               k;
    bnfa_match_node_t  ** MatchList;
    bnfa_match_node_t   * mlist;
    int              ps_index = 0;
    bnfa_state_t      * ps = 0;


    MatchList = bnfaMatchList.data();

    if (!bnfaNumStates)
        return;

    if (bnfaFormat == BNFA_SPARSE)
    {
        LogMessage("Print NFA-SPARSE state machine : %d active states\n",
            bnfaNumStates);
        ps = bnfaTransList.data();
        if (!ps)
            return;
    }

    for (k = 0; k < bnfaNumStates; k++)
    {
        LogMessage(" state %-4d fmt=%d ", k, bnfaFormat);

        if (bnfaFormat == BNFA_SPARSE)
        {
            unsigned i;
            unsigned fs, nt, fb, mb;
            bnfa_state_t cw;
            ps_index++; /* skip state number */

            cw = ps[ps_index]; /* control word  */

            /* full storage bit */
            fb = (cw &  BNFA_SPARSE_FULL_BIT) >> BNFA_SPARSE_VALUE_SHIFT;
            /* matching state bit */
            mb = (cw &  BNFA_SPARSE_MATCH_BIT) >> BNFA_SPARSE_VALUE_SHIFT;
            /* number of transitions 0-63 */
            nt = (cw &  BNFA_SPARSE_COUNT_BITS) >> BNFA_SPARSE_VALUE_SHIFT;
            /* fail state */
            fs = (cw &  BNFA_SPARSE_MAX_STATE) >> BNFA_SPARSE_VALUE_SHIFT;

            ps_index++;  /* skip control word */

            LogMessage("mb=%3u fb=%3u fs=%-4u ", mb, fb, fs);

            if (fb)
            {
                LogMessage(" nt=%-3d : ", bnfaAlphabetSize);

                for (i = 0; i < bnfaAlphabetSize; i++, ps_index++)
                {
                    if (ps[ps_index] == 0) continue;

                    if (isascii((int)i) && isprint((int)i))
                        LogMessage("%3c->%-6d\t", i, ps[ps_index]);
                    else
                        LogMessage("%3d->%-6d\t", i, ps[ps_index]);
                }
            }
            else
            {
                LogMessage(" nt=%-3d : ", nt);

                for (i = 0; i < nt; i++, ps_index++)
                {
                    int ch = ps[ps_index] >> BNFA_SPARSE_VALUE_SHIFT;
                    if (isascii(ch) &&
                        isprint(ch))
                        LogMessage("%3c->%-6d\t",
                        ch,
                        ps[ps_index] & BNFA_SPARSE_MAX_STATE);
                    else
                        LogMessage("%3d->%-6d\t",
                        ch,
                        ps[ps_index] & BNFA_SPARSE_MAX_STATE);
                }
            }
        }

        LogMessage("\n");

        if (MatchList[k])
            LogMessage("---MatchList For State %d\n", k);

        for (mlist = MatchList[k];
        mlist != nullptr;
            mlist = mlist->next)
        {
            bnfa_pattern_t * pat;
            pat = (bnfa_pattern_t*)mlist->data;
            LogMessage(
                "---pattern : %.*s\n",
                static_cast<int>(pat->n),
                reinterpret_cast<const char*>(pat->casepatrn.data()));
        }
    }
}

/*
*  Create a new AC state machine
*/
AhoCorasickSearch::AhoCorasickSearch(bnfa_case flag)
    :toupper_functor(toupper)
{
    bnfaPatterns = 0;
    bnfaMethod = 0; // use queue
    bnfaNumStates = 0;
    bnfaMaxStates = 0;
    bnfaNumTrans = 0;
    bnfaMatchStates = 0;
    bnfaTransTable.reset();

    bnfaPatternCnt = 0;
    bnfaOptimizeFailureStates = false;
    bnfaCaseMode = bnfa_case::BNFA_PER_PAT_CASE;
    bnfaFormat = BNFA_SPARSE;
    bnfaAlphabetSize = BNFA_MAX_ALPHABET_SIZE;

    bnfaForceFullZeroState = 1;
    bnfa_memory = sizeof(AhoCorasickSearch);
    pat_memory = 0;
    list_memory = 0;
    nextstate_memory = 0;
    failstate_memory = 0;
    matchlist_memory = 0;
    setCase(flag);
    max_queue = 32;
}

void
AhoCorasickSearch::setOptimizeFailureStates(bool flag)
{
    bnfaOptimizeFailureStates = flag;
}

void
AhoCorasickSearch::setCase(bnfa_case flag)
{
    if (flag == bnfa_case::BNFA_PER_PAT_CASE) bnfaCaseMode = flag;
    if (flag == bnfa_case::BNFA_CASE) bnfaCaseMode = flag;
    if (flag == bnfa_case::BNFA_NOCASE) bnfaCaseMode = flag;
}

void
AhoCorasickSearch::_reset_compiled_state()
{
    _bnfa_list_free_table();
    std::vector<bnfa_match_node_t*>().swap(bnfaMatchList);
    std::vector<std::unique_ptr<bnfa_match_node_t>>().swap(match_node_storage_);
    std::vector<bnfa_state_index_t>().swap(bnfaFailState);
    std::vector<bnfa_state_t>().swap(bnfaTransList);
    match_queue.clear();

    bnfaNumStates = 0;
    bnfaMaxStates = 0;
    bnfaNumTrans = 0;
    bnfaMatchStates = 0;

    matchlist_memory = 0;
    failstate_memory = 0;
    nextstate_memory = 0;
}

AhoCorasickSearch::bnfa_trans_node_t*
AhoCorasickSearch::_make_transition_node()
{
    auto node = std::make_unique<bnfa_trans_node_t>();
    bnfa_trans_node_t* raw_node = node.get();
    transition_node_storage_.push_back(std::move(node));
    list_memory += sizeof(bnfa_trans_node_t);
    return raw_node;
}

AhoCorasickSearch::bnfa_match_node_t*
AhoCorasickSearch::_make_match_node()
{
    auto node = std::make_unique<bnfa_match_node_t>();
    bnfa_match_node_t* raw_node = node.get();
    match_node_storage_.push_back(std::move(node));
    matchlist_memory += sizeof(bnfa_match_node_t);
    return raw_node;
}

AhoCorasickSearch::~AhoCorasickSearch() = default;


/*
*   Compile the patterns into an nfa state machine
*/
int
AhoCorasickSearch::compile()
{
    auto fail = [this]() {
        _reset_compiled_state();
        return -1;
    };

    try
    {
        _reset_compiled_state();

        bnfa_pattern_t* plist;
        unsigned cntMatchStates;
        unsigned i;

        /* Count number of states */
        for (plist = bnfaPatterns; plist != nullptr; plist = plist->next)
        {
            bnfaMaxStates += plist->n;
        }
        bnfaMaxStates++; /* one extra */

        /* Alloc a List based State Transition table */
        bnfaTransTable = std::make_unique<bnfa_trans_table_t>();
        bnfaTransTable->transitions.assign(bnfaMaxStates, nullptr);
        list_memory = sizeof(bnfa_trans_table_t) +
            bnfaTransTable->transitions.size() * sizeof(bnfa_trans_node_t*);

        /*
        ** Alloc a MatchList table -
        ** this has a list of pattern matches for each state
        */
        bnfaMatchList.assign(bnfaMaxStates, nullptr);
        matchlist_memory = bnfaMatchList.size() * sizeof(bnfa_match_node_t*);

        /* Add each Pattern to the State Table - This forms a keyword trie using lists */
        bnfaNumStates = 0;
        for (plist = bnfaPatterns; plist != nullptr; plist = plist->next)
        {
            if (_bnfa_add_pattern_states(plist))
            {
                return fail();
            }
        }
        bnfaNumStates++;

        if (bnfaNumStates > BNFA_SPARSE_MAX_STATE)
        {
            return fail();
        }

        /* ReAlloc a smaller MatchList table -  only need NumStates  */
        std::vector<bnfa_match_node_t*> resizedMatchList(bnfaNumStates);
        std::copy_n(bnfaMatchList.begin(), bnfaNumStates, resizedMatchList.begin());
        bnfaMatchList = std::move(resizedMatchList);
        matchlist_memory = bnfaMatchList.size() * sizeof(bnfa_match_node_t*) +
            match_node_storage_.size() * sizeof(bnfa_match_node_t);

        /* Alloc a failure state table -  only need NumStates */
        bnfaFailState.assign(bnfaNumStates, 0);
        failstate_memory = bnfaFailState.size() * sizeof(bnfa_state_index_t);

        /* Build the nfa w/failure states - time the nfa construction */
        if (_bnfa_build_nfa())
        {
            return fail();
        }

        /* Convert nfa storage format from list to full or sparse */
        if (bnfaFormat == BNFA_SPARSE)
        {
            if (_bnfa_conv_list_to_csparse_array())
            {
                return fail();
            }
            std::vector<bnfa_state_index_t>().swap(bnfaFailState);
            failstate_memory = 0;
        }
        else
        {
            return fail();
        }

        /* Free up the Table Of Transition Lists */
        _bnfa_list_free_table();

        /* Count states with Pattern Matches */
        cntMatchStates = 0;
        for (i = 0; i < bnfaNumStates; i++)
        {
            if (bnfaMatchList[i])
                cntMatchStates++;
        }

        bnfaMatchStates = cntMatchStates;

        return 0;
    }
    catch (const std::bad_alloc&)
    {
        return fail();
    }
}

/*
   binary array search on sparse transition array

   O(logN) search times
   data must be in sorted order in the array.

   return:  = -1 => not found
           >= 0  => index of element 'val'

  notes:
    val is tested against the high 8 bits of the 'a' array entry,
    this is particular to the storage format we are using.
*/


/* Queue whole pattern groups at end states in AC */
/* uniquely insert into q, should splay elements for performance */
int
AhoCorasickSearch::_add_queue(bnfa_match_node_t * p, int pos)
{
    bnfa_match_t match;
    match.data = p;
    match.pos = pos;
    match_queue_type::iterator itLookup = match_queue.lower_bound(match);
    if (itLookup == match_queue.end() || !(*itLookup == match))
    {
        match_queue.insert(itLookup, match); // use insertion point hint
    }
    return (match_queue.size() >= max_queue);
}





int
AhoCorasickSearch::getPatternCount()
{
    return bnfaPatternCnt;
}


/*
*  Info: Print info a particular state machine.
*/
void AhoCorasickSearch::printInfoEx(char * text)
{
    size_t max_memory;

    if (!bnfaNumStates)
    {
        return;
    }
    max_memory = bnfa_memory + pat_memory + list_memory +
        matchlist_memory + failstate_memory + nextstate_memory;

    LogMessage("+-[AC-BNFA Search Info]------------------------------\n");
    LogMessage("| Patterns         : %d\n", bnfaPatternCnt);
    LogMessage("| Pattern Chars    : %d\n", bnfaMaxStates);
    LogMessage("| Num States       : %d\n", bnfaNumStates);
    LogMessage("| Num Match States : %d\n", bnfaMatchStates);
    if (max_memory < 1024 * 1024)
    {
        LogMessage("| Memory           :   %.2fKbytes\n", (double)max_memory / 1024);
        LogMessage("|   Patterns       :   %.2fK\n", (double)pat_memory / 1024);
        LogMessage("|   Match Lists    :   %.2fK\n", (double)matchlist_memory / 1024);
        LogMessage("|   Transitions    :   %.2fK\n", (double)nextstate_memory / 1024);
    }
    else
    {
        LogMessage("| Memory           :   %.2fMbytes\n",
            static_cast<double>(max_memory) / (1024 * 1024));
        LogMessage("|   Patterns       :   %.2fM\n",
            static_cast<double>(pat_memory) / (1024 * 1024));
        LogMessage("|   Match Lists    :   %.2fM\n",
            static_cast<double>(matchlist_memory) / (1024 * 1024));
        LogMessage("|   Transitions    :   %.2fM\n",
            static_cast<double>(nextstate_memory) / (1024 * 1024));
    }
    LogMessage("+-------------------------------------------------\n");
}
void AhoCorasickSearch::printInfo() {
    printInfoEx(0);
}

} // namespace
