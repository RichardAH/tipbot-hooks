/**
 * Non-custodial Tip bot Hook 2: Withdraw-deposit (Top up hook or just Top)
 * Author: Richard Holland
 * Date: 14/3/26
 * Description:
 *  Allows deposit and withdrawal from the non-custodial tipbot.
 *  This hook should only be set to HookOn remit.
 */

/* Withdraw-Deposit Hook Constraints:
 * Only Remit transactions accepted.
 * Exactly one parameter provided on each Remit
 * No NFTs allowed on remits
 * Either 0 or 1 currency provided on each Remit (0 for withdraw, 1 for deposit)
 * To withdraw:
 *  User first xfers their balance by tipping it to an r-address (on the social network)
 *  Tip Oracle Hook will credit a user balance key of the form sha512h(accid . currency . issuer)
 *  User sends an empty Remit to this Hook with a parameter "WITHDRAW" -> 48 bytes: currency . issuer . xflamt
 *  If there is a positive balance on that key for the otxn account then the amount is withdrawn
 *  If if the amount is greater than the balance then the whole balance is withdrawn
 *  The withdrawal is emitted as a remit back to the otxn account, but only if the otxn account has the needed TL.
 * To deposit:
 *  User sends a Remit with exactly one Amount in it to this Hook.
 *  Remit contains a single parameter "DEPOSIT" -> snid . 11x zero bytes . userid
 *  Remit will create the TL on the Hook acc if needed.
 * Notes:
 *  If there is a pending hook change due to governance vote then that is also emitted during any call to this hook.
 */

#include <stdint.h>
#include "hookapi.h"

#define SVAR(x) &(x), sizeof(x)
#define DONE(x) accept((x), sizeof(x), __LINE__)
#define NOPE(x) rollback((x), sizeof(x), __LINE__)
#define ttREMIT 95U

#define COPY20(src,dst)\
{\
    uint32_t* x = (dst);\
    uint32_t* y = (src);\
    *x++ = *y++;\
    *x++ = *y++;\
    *x++ = *y++;\
    *x++ = *y++;\
    *x++ = *y++;\
}

#define COPY40(src,dst)\
{\
    uint64_t* x = (dst);\
    uint64_t* y = (src);\
    *x++ = *y++;\
    *x++ = *y++;\
    *x++ = *y++;\
    *x++ = *y++;\
    *x++ = *y++;\
}

// state keys:
// 'H' pos         - voting said hook hash can be installed at this position (action by other hook)
// 'B' balhash     - user-currency-issuer balance hashes
// user info below contains a catalogue of which balances are held by a given user.
// 'U' useracc     - snid.11zeros.userid or accid -> 256 bit field containing keys to balances held
// 'U' useracc . c - as above but with a one byte indicator as per bit field -> validly held balance hash

uint8_t txn_remit[60000] =
{
/* size,upto */
/*   3,   0 */   0x12U, 0x00U, 0x5FU,                                                           /* tt = Remit       */
/*   5,   3 */   0x22U, 0x80U, 0x00U, 0x00U, 0x00U,                                          /* flags = tfCanonical */
/*   5,   8 */   0x24U, 0x00U, 0x00U, 0x00U, 0x00U,                                                 /* sequence = 0 */
/*   6,  13 */   0x20U, 0x1AU, 0x00U, 0x00U, 0x00U, 0x00U,                                      /* first ledger seq */
/*   6,  19 */   0x20U, 0x1BU, 0x00U, 0x00U, 0x00U, 0x00U,                                       /* last ledger seq */
/*   9,  25 */   0x68U, 0x40U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,                         /* fee      */
/*  35,  34 */   0x73U, 0x21U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,       /* pubkey   */
/*  22,  69 */   0x81U, 0x14U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                                  /* srcacc  */
/*  22,  91 */   0x83U, 0x14U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                                  /* dstacc  */
/* 116, 113 */   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,    /* emit detail */
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,

/*   2, 229 */  0xF0U, 0x5CU,                                                               /* lead-in amount array */
/*   2, 231 */  0xE0U, 0x5BU,                                                               /*lead-in amount entry A*/
/*  49, 233 */  0x61U,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                                                /* amount A */
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/*   2, 282 */  0xE1, 0xF1                                                                              /* lead out */
/*   -, 290 */
};

#define TXN_CUR_A (txn_remit + 233)
#define OTXNACC (txn_remit + 93)
#define HOOKACC (txn_remit + 71)
#define TXN_EDET (txn_remit + 113)

#define BE_DROPS(drops)\
{\
    uint64_t drops_tmp = drops;\
    uint8_t* b = (uint8_t*)&drops;\
    *b++ = 0b01000000 + (( drops_tmp >> 56 ) & 0b00111111 );\
    *b++ = (drops_tmp >> 48) & 0xFFU;\
    *b++ = (drops_tmp >> 40) & 0xFFU;\
    *b++ = (drops_tmp >> 32) & 0xFFU;\
    *b++ = (drops_tmp >> 24) & 0xFFU;\
    *b++ = (drops_tmp >> 16) & 0xFFU;\
    *b++ = (drops_tmp >>  8) & 0xFFU;\
    *b++ = (drops_tmp >>  0) & 0xFFU;\
}

uint8_t amt_buf[50];
uint8_t req[69] = {'U'};

int64_t hook(uint32_t r)
{
    _g(1,1);
    etxn_reserve(2);

    // pass outgoing txns
    otxn_field(OTXNACC, 20, sfAccount);

    hook_account(HOOKACC, 20);

    if (BUFFER_EQUAL_20(HOOKACC, OTXNACC))
        DONE("Top: Passing outgoing txn.");

    // pass all non-remits
    if (otxn_type() != ttREMIT)
        DONE("Top: Passing non-remit.");

    // validate remit
    otxn_slot(1);

    if (slot_subfield(1, sfURITokenIDs, 2) != DOESNT_EXIST)
        NOPE("Top: Remit cannot contain URITokenIDs.");

    if (slot_subfield(1, sfMintURIToken, 2) != DOESNT_EXIST)
        NOPE("Top: Remit cannot contain MintURIToken.");

    if (slot_subfield(1, sfAmounts, 2) != DOESNT_EXIST)
    {
        // this is a deposit
        if (slot_count(2) != 1 || slot_subarray(2, 0, 2) != 2) // || slot_subfield(2, sfAmount, 2) != 2)
            NOPE("Top: Remit must contain either one amount (for deposit) or no sfAmounts field (for withdraw).");

        slot(SBUF(amt_buf), 2);

        int64_t is_xah = (slot_type(2, 1) == 1);

        // find the user's id from the parameter
        uint8_t to_key[61] = {'U'};
        if (otxn_param(to_key + 1, 20, "DEPOSIT", 7) != 20)
            NOPE("Top: Remit missing DEPOSIT HookParameter containing u8:SNID.11x0bytes.u64:USERID.");

        if (to_key[1] == 0 || to_key[1] >= 254)
            NOPE("Top: Remit attempting to deposit to invalid SNID (try 1 for twitter.)");

        // to prevent laundering etc we prevent depositing to an accid account, we do this by enforcing the 11x0s
        if (*((uint64_t*)(to_key + 2)) != 0 || *((uint32_t*)(to_key + 9)) != 0)
            NOPE("Top: Can only top-up an social network tip account, not a withdrawal address!");

        // execution to here means we have a valid snid.0s.userid to build the key out of
        // next populate the remaining key information,
        // xah is represented by all 0's in cur and issuer, which is the case if slot call above didn't populate
        // the end of the array, which is the case if the slot contains xah, so this code can be branchless

        // E = obj start byte
        // F = obj end byte
        // A = amount bytes
        // C = currency bytes
        // I = issuer bytes
        //          XXXXXXXXYYYYYYYYZZZZZZZZXXXXXXXXYYYYYYYY
        // 0         1         2         3         4
        // 01234567890123456789012345678901234567890123456789
        // EAAAAAAAACCCCCCCCCCCCCCCCCCCCIIIIIIIIIIIIIIIIIIIIF
        //
        COPY40(amt_buf + 9U, to_key + 21U);

        int64_t amt = slot_float(2);

        if (amt <= 0)
            NOPE("Top: Invalid amount deposited (somehow?).");

        // credit the user
        uint8_t to_key_hash[32];
        util_sha512h(SBUF(to_key_hash), to_key + 1, 60);

        to_key_hash[0] = 'B';
        uint8_t to_bal_buf[9];

        state(SBUF(to_bal_buf), SBUF(to_key_hash));

        int64_t to_bal = *((uint64_t*)(to_bal_buf));
        uint8_t to_idx = *((uint8_t*)(to_bal_buf + 8U));

        uint8_t to_user_info[32];

        // to prevent attacks, the first deposit to a new user must be xah and must be at least 10 xah
        if (state(SBUF(to_user_info), to_key, 21) != 32)
        {
            if (!is_xah || float_compare(amt, 6107881094714392576ULL /* 10.0 */, COMPARE_LESS) == 1)
                NOPE("Top: First deposits must be in XAH and must be at least 10 XAH.");
        }

        int64_t final_to_bal = float_sum(to_bal, amt);
        if (float_compare(final_to_bal, to_bal, COMPARE_LESS | COMPARE_EQUAL) == 1)
            NOPE("Top: Insane result adding to to-balance.");

        if (to_bal == 0)
        {

            // if the to-user didn't have this currency before this xfer we need to "slot-in" a new currency
            // that they are holding according to their userinfo card
            // we do that by finding the lowest available 0 bit in the 256 bit field on the user info key
            uint64_t* w = (uint64_t *)to_user_info;
            uint64_t v;

            if      ((v = ~w[0])) to_idx =       __builtin_ctzll(v);
            else if ((v = ~w[1])) to_idx =  64 + __builtin_ctzll(v);
            else if ((v = ~w[2])) to_idx = 128 + __builtin_ctzll(v);
            else if ((v = ~w[3])) to_idx = 192 + __builtin_ctzll(v);
            else
                NOPE("Top: Can't credit a new currency to this user. At limit of 256.");

            to_user_info[to_idx >> 3] |= (uint8_t)(1U << (to_idx % 8U));
            // we'll clober some data in the to_key buffer to construct this user info entry
            // 'U'. snid . 11 zeros . userid . idx, or
            // 'U' . accid . idx
            // 0         1         2
            // 0123456789012345678901
            // UAAAAAAAAAAAAAAAAAAAAI
            // US00000000000UUUUUUUUI
            // maps to currency . issuer (pulled from opinion field)
            to_key[21] = to_idx;

            state_set(amt_buf +  9U, 40, to_key, 22);

            // update the user info to reflect the index
            state_set(SBUF(to_user_info), to_key, 21);

            to_bal_buf[8] = to_idx;
        }

        *((uint64_t*)to_bal_buf) = final_to_bal;
        state_set(SBUF(to_bal_buf), SBUF(to_key_hash));
        DONE("Top: Credited top-up to user.");
    }

    // execution to here means empty remit (i.e. a withdrawal)

    // preifx the request buffer with the accid so we can do a balance lookup easily
    COPY20(OTXNACC, req + 1U);

    if (otxn_param(req + 21U, 48, "WITHDRAW", 8) != 48)
        NOPE("Top: Remit missing WITHDRAW HookParameter containing 20 byte cur . 20 byte iss . 8 byte xfl amt.");

    // this buffer looks like:
    // A - accid
    // C - currency id
    // I - issuer id
    // X - xfl 8 byte le amount
    // U - the character U
    //
    // 0         1         2         3         4         5         6
    // 0123456789012345678901234567890123456789012345678901234567890123456789
    // UAAAAAAAAAAAAAAAAAAAACCCCCCCCCCCCCCCCCCCCIIIIIIIIIIIIIIIIIIIIXXXXXXXX

    int64_t is_xah = 
       (*((uint64_t*)(req + 21U)) == 0 &&
        *((uint64_t*)(req + 29U)) == 0 &&
        *((uint64_t*)(req + 37U)) == 0 &&
        *((uint64_t*)(req + 45U)) == 0 &&
        *((uint64_t*)(req + 53U)) == 0);

    uint8_t from_key_hash[32];
    util_sha512h(SBUF(from_key_hash), req + 1, 60);

    from_key_hash[0] = 'B';

    uint8_t from_bal_buf[9];
    if (state(SBUF(from_bal_buf), SBUF(from_key_hash)) != 9)
        NOPE("Top: No such user-currency-issuer pair / balance.");

    int64_t from_bal = *((uint64_t*)(from_bal_buf));
    uint8_t from_idx = *((uint8_t*)(from_bal_buf + 8U));

    int64_t reqxfl = *((uint64_t*)(req + 61U));

    if (reqxfl <= 0 || float_compare(reqxfl, 0, COMPARE_LESS | COMPARE_EQUAL) == 1)
        NOPE("Top: Insane or negative withdraw amount.");

    if (from_bal <= 0 || float_compare(from_bal, 0, COMPARE_LESS | COMPARE_EQUAL) == 1)
        NOPE("Top: Insane or negative from balance.");

    // if they request more than their balance then send the whole thing

    if (float_compare(from_bal, reqxfl, COMPARE_LESS | COMPARE_EQUAL) == 1)
    {
        // delete the balance from the hook because we're sending all
        reqxfl = from_bal;
        // delete the balance entry
        state_set(0,0, SBUF(from_key_hash));

        // update the index to mark it as clear on the userinfo card
        uint8_t from_user_info[32];
        if (state(SBUF(from_user_info), req, 21) == 32)
        {
            from_user_info[from_idx >> 3U] &= ~((uint8_t)(1U << (from_idx % 8U)));
            state_set(SBUF(from_user_info), req, 21);
        }
    }
    else
    {
        // subtract and update the balance
        int64_t final_from_bal = float_sum(from_bal, float_negate(reqxfl));
        if (float_compare(final_from_bal, from_bal, COMPARE_GREATER | COMPARE_EQUAL))
            NOPE("Top: Insane final balance sum result.");
        *((uint64_t*)(from_bal_buf)) = final_from_bal;
        state_set(SBUF(from_bal_buf), SBUF(from_key_hash));
    }


    // check the receiver has the needed TL
    if (!is_xah)
    {
        uint8_t keylet[34];
        if (util_keylet(keylet, 34, KEYLET_LINE,
                  OTXNACC, 20,
                  req + 41U, 20U,
                  req + 21U, 20U) != 34)
            NOPE("Top: Internal error generating keylet.");

        if (slot_set(SBUF(keylet), 3) != 3)
            NOPE("Top: Trustline for this currency does not exist on your account.");
    }

    // honour reqxfl

    float_sto(TXN_CUR_A, 49, req + 21U, 20, req + 41U, 20, reqxfl, sfAmount);

    int64_t bytes = 284;

    // if the output is xah then we need to rewrite and shorten the amounts field
    // for the alternative (native) integer format of xah
    if (is_xah)
    {
        int64_t drops = float_int(reqxfl, 6, 0);
        if (drops <= 0 || float_compare(float_set(6, drops), reqxfl, COMPARE_GREATER) == 1)
            NOPE("Top: Insane drops computation.");

        BE_DROPS(drops);
        bytes -= 40;

        *((uint64_t*)(TXN_CUR_A + 1U)) = drops;
        
        *(TXN_CUR_A +  9U) = 0xE1U;
        *(TXN_CUR_A + 10U) = 0xF1U;
    }
    etxn_details(TXN_EDET, 116);
    int64_t fee = etxn_fee_base(txn_remit, bytes);
    BE_DROPS(fee);
    *((uint64_t*)(txn_remit + 26)) = fee;
    int64_t seq = ledger_seq() + 1;
    txn_remit[15] = (seq >> 24U) & 0xFFU;
    txn_remit[16] = (seq >> 16U) & 0xFFU;
    txn_remit[17] = (seq >>  8U) & 0xFFU;
    txn_remit[18] = seq & 0xFFU;
    seq += 4;
    txn_remit[21] = (seq >> 24U) & 0xFFU;
    txn_remit[22] = (seq >> 16U) & 0xFFU;
    txn_remit[23] = (seq >>  8U) & 0xFFU;
    txn_remit[24] = seq & 0xFFU;
    trace(SBUF("emit:"), txn_remit, bytes, 1);
    uint8_t emithash[32];
    int64_t emit_result = emit(SBUF(emithash), txn_remit, bytes);
    if (DEBUG)
        TRACEVAR(emit_result);
    if (emit_result < 0)
        rollback(SBUF("Top: Emit failed."), __LINE__);

    // RHTODO: cbak on failure and hookhash action
}
