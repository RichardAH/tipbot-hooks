/**
 * Non-custodial Tip bot Hook
 * Author: Richard Holland
 * Date: 20/2/26
 * Description:
 *  Supports tipping on social media platforms (especially twitter/X, netid=1)
 *  Tip actions are monitored by tipbot oracle nodes
 *  Nodes vote on which tips they saw, the amount, the to and from (oracle game)
 *  Hook actions tip after meeting vote quorum
 *  Tipbot Oracle Nodes (TONs) also participate in a governance game
 *  to maintain who is a valid TON according to the Hook.
 */

#include <stdint.h>
#include "hookapi.h"

#define SVAR(x) &(x), sizeof(x)
#define DONE(x) accept((x), sizeof(x), __LINE__)
#define NOPE(x) rollback((x), sizeof(x), __LINE__)


/* Oracle game:
 * Parameter keys: 0..F
 * Parameter values: (le)
 * bytes : type : desc
 * -------------------
 * 00-00 :  u8  : social network ID (1 = twitter, 0 = no more params, 254 = member voting, 255 = hook voting)
 * 01-08 : u64  : post ID
 * 09-28 : var  : user ID to (if first 12 bytes are 0) else accid to
 * 29-36 : u64  : user ID from
 * 37-56 : cur  : currency code
 * 57-76 : acc  : issuer accid
 * 77-84 : xfl  : amount tipped
 */

// cleanup keys are bounded by the values at these two keys
uint8_t cleanup_key_highwater[32] = {'S', 'H'};
uint8_t cleanup_key_lowwater[32] = {'S', 'L'};

uint8_t members_bitfield_key[32] = {'S', 'M'};

uint8_t cleanup_key_lower[32] = {'C'};
uint64_t cleanup_key_upper[32] = {'C'};

uint64_t* cleanup_lower = cleanup_key_lower + 1;
uint64_t* cleanup_upper = cleanup_key_upper + 1;

uint8_t otxn_acc[21] = { 'M' };

uint8_t opinion[87] = { 'O' };

// state keys:
// 'S' L/H/M       - special keys above: low water mark, high water mark (for gc), m for member bit field
// 'M' accid       - accid -> seat id
// 'P' seatid      - seat (pos) id -> accid
// 'C' cleaupid    - cleanupid->cleanup key
// 'O' opinion     - snid.postid->post_info
// 'H' pos         - voting said hook hash can be installed at this position (action by other hook)
// 'B' balhash     - user-currency-issuer balance hashes
/*  Result codes:
        D  = Actioned already (done)
        V  = Voted already
        S  = Submitted vote
        A  = Actioned now
        B  = Can't action because balance of sender is too low
       ' ' = No opinion in this slot
*/
uint8_t donemsg[] = "Tip: 00 Opinions processed. Results:                 ";
uint8_t* tens = (donemsg + 5U);
uint8_t* ones = (donemsg + 6U);
int64_t hook(uint32_t r)
{
    _g(1,1);

    uint32_t current_ledger = ledger_seq();
    uint32_t cutoff_ledger = current_ledger - 20U;

    // pickup the gc boundaries, these represent which keys to examine for amortized removal
    state(cleanup_key_upper + 1, 8, SBUF(cleanup_key_highwater));
    state(cleanup_key_lower + 1, 8, SBUF(cleanup_key_lowwater));
    
    // try to clean up 16 entries
    for (int i = 0; GUARD(16), *cleanup_lower < *cleanup_upper && i < 16; ++i, ++*cleanup_lower)
    {
        uint8_t val[256];
        int64_t len;
        // all values start with the ledger in which they were created
        if ((len = state(SBUF(val), SBUF(cleanup_key_lower))) < 4 ||
            *((uint32_t*)val) > cutoff_ledger)
            break;

        // delete the entry pointed to
        state_set(0, 0, val, len);

        // delete the cleanup entry
        state_set(0, 0, SBUF(cleanup_key_lower));
    }
    
    state_set(cleanup_lower, 8,  SBUF(cleanup_key_lowwater));
 
    // we've done amortized cleanup, so early ending will always be via DONE, so we get the cleanup processing
    // done even if there was an error   

    otxn_field(otxn_acc + 1, 20, sfAccount);

    uint8_t hook_acc[20];
    hook_account(SBUF(hook_acc));

    if (BUFFER_EQUAL_20(hook_acc, (otxn_acc+1)))
        DONE("Tip: Passing outgoing txn.");

    uint16_t tt;
    otxn_field(SVAR(tt), sfTransactionType);
    if (tt != ttINVOKE)
        DONE("Tip: Passing non-invoke.");

    // first check if they are a member of the game
    uint8_t member_id;
    if (state(SVAR(member_id), SBUF(otxn_acc)) != 1)
        DONE("Tip: You're not a member of the tipbot oracle game. Did some cleanup anyway.");
   
    // execution to here means they're a member 
    uint8_t const member_id_byte = member_id >> 3;
    uint8_t const member_id_bit = member_id % 8;

    uint8_t members_bitfield[32];
    state(SBUF(members_bitfield), SBUF(members_bitfield_key));

    // the members bit field is a 256 bit field where the left most bit (msb) indicates if the seat for member 0
    // is occupied and the right most bit (lsb) indicates if the seat for member 256 is occupied. we count the set
    // bits using a wasm intrinsic called popcnt, and this gives us the total current membership of the smart contract
    // we count the members by dividing the bit field into 4 lots of u64
    uint8_t member_count =
            __builtin_popcountll(*((uint64_t*)(members_bitfield +  0))) +
            __builtin_popcountll(*((uint64_t*)(members_bitfield +  8))) +
            __builtin_popcountll(*((uint64_t*)(members_bitfield + 16))) +
            __builtin_popcountll(*((uint64_t*)(members_bitfield + 24)));
    
    if (member_count == 0)
        NOPE("Tip: Misconfigured, no members.");    

    // threshold for actioning a tip is >50% of the members
    uint8_t threshold = member_count >> 1U;

    // logic for threshold follows.
    // maintain a super majority at any cost with as little computation as possible:
    // if we have 1 member  then 1 >> 1U == 0, so increment to 1    (1/1 == 100%)
    // if we have 2 members then 2 >> 1U == 1, so increment to 2    (2/2 == 100%)
    // if we have 3 members then 3 >> 1U == 1, so increment to 2    (2/3 ==  66%)
    // if we have 4 members then 4 >> 1U == 2, so increment to 3    (3/4 ==  75%)
    // if we have 5 members then 5 >> 1U == 2, so increment to 3    (3/5 ==  60%)
    // if we have 6 members then 6 >> 1U == 3, so increment to 4    (4/6 ==  66%)
    // and so on
    threshold++;


#define SNID   *((uint8_t*)(opinion +  0U))
#define POSTID *((uint64_t*)(opinion +  1U))
#define FROMID *((uint64_t*)(opinion + 29U))
#define FROMID_PTR ((uint64_t*)(opinion + 29U))
// only if tip isn't to an r-addr
#define TOID   *((uint64_t*)(opinion + 21U))
// only if tip is to an r-addr
#define TOACC  (opinion + 9U)
// whether the tip is to an r-addr or not
#define IS_TOACC  (\
        *((uint64_t*)(opinion + 9U)) == 0 &&\
        *((uint32_t*)(opinion + 17U)) == 0)
#define CUR    (opinion + 37U)
#define ISS    (opinion + 57U)
#define AMTXFL *((uint64_t*)(opinion + 77U))

    // process opinions
    int i = 0;
    uint8_t* donemsg_upto = donemsg + 37;
    for (; GUARD(16), i < 16; ++i, ++donemsg_upto)
    {
        if (i == 10)
            (*tens)++;

        otxn_param(opinion + 1, 86, &i, 1);
        
        // a social network id of 0 is the same as stop processing
        if (!SNID)
            break;

        // get some information about the post... the ledger it first appeared in
        // whether any xfer on it has been actioned, and who voted
        uint8_t post_info[37];
        /*
            key: netid-postid (u8.u64)
            value: 37 bytes comprisning--
            byte : type : desc
            0-3  : u32  : ledger seq first appearing in
            4-4  : u8   : 1=actioned, 0=not yet actioned
            5-36 : b256 : bit field of member ids who have voted with msb being member 255
        */

        // we'll set the ledger_seq before calling the state recall api, that way if the state doesn't exist
        // the ledger_seq is pre-loaded into the field, and if it does exist it's overriden by the contents
        // of the state entry. this way only the ledger_seq of the first vote (temporaly) is recorded
    
        *((uint32_t*)post_info) = current_ledger;

        if (state(post_info, 37, opinion, 10 /*    'O' . netid . 8 bytes of post id, 
                                                or 'O' . 254   . 1 byte position . 7 bytes lead bytes accid, 
                                                or 'O' . 255   . 1 byte position . 7 bytes lead bytes hhash */) < 0)
        {   
            // add a cleanup key if the entry doesn't exist 
            state_set(opinion, 10, SBUF(cleanup_key_upper));
            cleanup_upper++;
        }

        if (post_info[4])
        {
            // tip already actioned
            *donemsg_upto = 'D';
            continue;
        }
        
        // check if user already voted in on this post        
        if ((post_info[5 + member_id_byte] >> member_id_bit) & 1)
        {
            // already voted
            *donemsg_upto = 'V';
            continue;
        }

        *donemsg_upto = 'S';

        // record vote
        post_info[5 + member_id_byte] |= (1U << member_id_bit);

        // now we've processed the general infomation about the post, process the specific information
        // about this opinion expressed by the oracle game member (who xfer'd what to whom)

        // increment the vote counter for this specific position on this post
        uint8_t votes[5];
        *((uint32_t*)votes) = current_ledger; // all values are prefixed with ledger seq for cleanup
        state(SBUF(votes), SBUF(opinion));

        votes[4]++;
        state(SBUF(votes), SBUF(opinion));
        
        // assign a cleanup key if this is a new opinion
        if (votes[4] == 1)
        {
            state_set(SBUF(opinion), SBUF(cleanup_key_upper));
            ++*cleanup_upper;
        }

        // check if the threshold is met (>50% of members)
        if (votes[4] >= threshold)
            post_info[4] = 1;

        // update postinfo
        state_set(post_info, 37, opinion, 9);
           
        // only continue past this point if we're actioning the tip
        if (!post_info[4])
            continue;

        *donemsg_upto = 'A';

        // first mark it as actioned so we don't do it twice
        post_info[4] = 1;

        // check if the from user has balance to cover
        
        // balances key (sha512h hashed):
        // bytes : type : desc
        // 00-19 : xahau accid or snetid(1 byte)..00..userid(8 bytes)
        // 20-39 : cur  : 20 byte currency code (zeros for xah)
        // 40-59 : acc  : 20 byte issuer accid  (zeros for xah)
      
        // RHUPTO: fix balances keys ensure they are hashed properly as above
        // fix state_foreign stuff, adjust for 1 byte snetid everywhere no namespaces
        // member and hook vote actioning on snetids 254 and 255 
        
        /*
        opinion binary layout: 
        S = Social network id (u8)
        P = Post id (u64)                           
        T = Send to (accid or social network userid u64 LE) 
        F = Sent from (social network userid u64 LE)          
        C = Cur code
        I = Issuer Addr
        A = XFLAmt
        
        M = member accid (zero account to remove member)
        D = member slot (position 0 - 255)
        H = Hook Hash
        L = Hook position

        There are three different types of opinion: tip voting, member voting and hook voting.

        0         1         2         3         4         5         6         7         8
        0123456789012345678901234567890123456789012345678901234567890123456789012345678901234
 tip    SPPPPPPPPTTTTTTTTTTTTTTTTTTTTFFFFFFFFCCCCCCCCCCCCCCCCCCCCIIIIIIIIIIIIIIIIIIIIAAAAAAAA
 mem    SDMMMMMMMMMMMMMMMMMMMM000000000000000000000000000000000000000000000000000000000000000
 hook   SLHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH000000000000000000000000000000000000000000000000000
        */ 

        if (opinion[0] == 255)
        {
            // action hook change
            // because this requires an emit we don't handle it inside this large loop
            // rather set a state entry that lets another hook do the emit
            uint8_t key[2] = { 'H', opinion[1] };
            state_set(opinion + 2, 32, SBUF(key));
            continue;
        }

        if (opinion[0] == 254)
        {
            // action member voting
            uint8_t memacc[21] = {'M'};
            uint8_t pos[2] = {'P', opinion[1]};
            
            // always delete a member even if its already empty
            members_bitfield[opinion[1] >> 3] &= ~(1U << (opinion[1] % 8));
            state(memacc + 1, 20,  SBUF(pos));
            state_set(0,0, SBUF(memacc));
            state_set(0,0, SBUF(pos));

            if (!((*((uint64_t*)(opinion + 2)) == 0 && 
                *((uint64_t*)(opinion + 10)) == 0 && 
                *((uint32_t*)(opinion + 18)) == 0)))
            {
                // if the specified acc isnt the zero account we'll add a member too
                // add a member
                members_bitfield[opinion[1] >> 3] |= (1U << (opinion[1] % 8));
                // copy accid into member key
                *((uint64_t*)(memacc+1)) = *((uint64_t*)(opinion + 2));
                *((uint64_t*)(memacc+9)) = *((uint64_t*)(opinion + 10));
                *((uint32_t*)(memacc+17)) = *((uint32_t*)(opinion + 18));

                // add member key
                state_set(opinion + 1, 1, SBUF(memacc));

                // add reverse key
                state_set(memacc + 1, 20, SBUF(pos)); 
                
            }
            
            // update bitfield
            state(SBUF(members_bitfield), SBUF(members_bitfield_key));
            continue;
        }

        uint8_t from_key[60] = {SNID};

        *((uint64_t*)(from_key + 12U)) = FROMID;
        *((uint64_t*)(from_key + 20U)) = *((uint64_t*)(opinion + 37U));  // first 8 bytes of currency
        *((uint64_t*)(from_key + 28U)) = *((uint64_t*)(opinion + 45U));  // second 8 bytes of currency
        *((uint64_t*)(from_key + 36U)) = *((uint64_t*)(opinion + 53U));  // last 4 bytes of currency, first 4 of iss
        *((uint64_t*)(from_key + 44U)) = *((uint64_t*)(opinion + 61U));  // middle 8 bytes of issuer
        *((uint64_t*)(from_key + 52U)) = *((uint64_t*)(opinion + 69U));  // last 8 bytes of issuer

        uint8_t to_key[60] = {SNID};
        if (IS_TOACC)
        {
            *((uint64_t*)(to_key + 0U)) = *((uint64_t*)(TOACC + 0U));
            *((uint32_t*)(to_key + 8U)) = *((uint32_t*)(TOACC + 8U));
        } 
        *((uint64_t*)(to_key + 12U)) = TOID;
        
        *((uint64_t*)(to_key + 20U)) = *((uint64_t*)(opinion + 37U));  // first 8 bytes of currency
        *((uint64_t*)(to_key + 28U)) = *((uint64_t*)(opinion + 45U));  // second 8 bytes of currency
        *((uint64_t*)(to_key + 36U)) = *((uint64_t*)(opinion + 53U));  // last 4 bytes of currency, first 4 of iss
        *((uint64_t*)(to_key + 44U)) = *((uint64_t*)(opinion + 61U));  // middle 8 bytes of issuer
        *((uint64_t*)(to_key + 52U)) = *((uint64_t*)(opinion + 69U));  // last 8 bytes of issuer

        
        uint8_t from_key_hash[32];
        util_sha512h(SBUF(from_key_hash), SBUF(from_key));
        uint8_t to_key_hash[32];
        util_sha512h(SBUF(to_key_hash), SBUF(to_key));

        from_key_hash[0] = 'B';
        to_key_hash[0] = 'B';

        int64_t from_bal;
        // the balances key for the from address is already encoded inside the opinion 
        state(SVAR(from_bal), SBUF(from_key_hash));

        // check if the balance can even cover the xfer
        if (float_compare(from_bal, AMTXFL, COMPARE_LESS) == 1)
        {
            // cannot action the tip, the from balance is too small
            *donemsg_upto = 'B';
            continue;
        }

        // subtract the from balance
        int64_t final_from_bal = float_sum(from_bal, float_negate(AMTXFL));
        if (final_from_bal < 0 || float_compare(final_from_bal, from_bal, COMPARE_GREATER | COMPARE_EQUAL) == 1)
        {
            // not a sane result, skip / internal error
            *donemsg_upto = 'E';
            continue;
        }
        
        int64_t to_bal;
        state(SVAR(to_bal), SBUF(to_key_hash));

        int64_t final_to_bal = float_sum(to_bal, AMTXFL);

        if (final_to_bal < 0 || float_compare(final_to_bal, to_bal, COMPARE_LESS) == 1)
        {
            // internal error / overflow / insane result
            *donemsg_upto = 'O';
            continue;
        }
        
        // update from balance
        if (final_from_bal == 0)
            state_set(0,0, SBUF(from_key_hash));
        else
            state_set(SVAR(final_from_bal), SBUF(from_key_hash));

        // update to balance
        if (final_to_bal == 0)
            state_set(0,0, SBUF(to_key_hash));
        else
            state_set(SVAR(final_to_bal), SBUF(to_key_hash));
    }
    
    // update the cleanup boundaries
    state_set(cleanup_upper, 8,  SBUF(cleanup_key_highwater));

    *tens += i / 10;
    *ones += i % 10;

    DONE(donemsg);
}

