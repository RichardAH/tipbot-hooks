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
#define ttREMIT 0x5F00U

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

#define COPY32(src,dst)\
{\
    uint64_t* x = (dst);\
    uint64_t* y = (src);\
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

uint8_t txn_remit[284] =
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
};

uint8_t txn_sethook[306] =
{
/* size,upto */
/*   3,   0 */   0x12U, 0x00U, 0x16U,                                                           /* tt = HookSet     */
/*   5,   3 */   0x22U, 0x80U, 0x00U, 0x00U, 0x00U,                                          /* flags = tfCanonical */
/*   5,   8 */   0x24U, 0x00U, 0x00U, 0x00U, 0x00U,                                                 /* sequence = 0 */
/*   6,  13 */   0x20U, 0x1AU, 0x00U, 0x00U, 0x00U, 0x00U,                                      /* first ledger seq */
/*   6,  19 */   0x20U, 0x1BU, 0x00U, 0x00U, 0x00U, 0x00U,                                       /* last ledger seq */
/*   9,  25 */   0x68U, 0x40U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,                         /* fee      */
/*  35,  34 */   0x73U, 0x21U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,       /* pubkey   */
/*  22,  69 */   0x81U, 0x14U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                                  /* srcacc  */
/* 116,  91 */   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,    /* emit detail */
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/*  place 18 nops here, so that the hook set can be offset to any of the 10 locations by changing the number
    of empty objects ahead of the hooksetobj */
/*  18, 207 */  0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U,
                0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U,
/*   1, 225 */  0xFBU,                                                                      /* lead-in  hooks array */
/*   1, 226 */  0xEEU,                                                                      /* lead-in hook entry 1 */
/*   4, 227 */  0x10U, 0x14U, 0x00U, 0x00U,                                                 /* hookapiversion=0     */
/*   5, 231 */  0x22U, 0x00U, 0x00U, 0x00U, 0x001U,                                         /* flags = hsfOverride  */
/*  34, 236 */  0x50U, 0x14U,
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,            /* hookon */
/*  34, 270 */  0x50U, 0x1FU, 
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,            /* hookhash */
/*   2, 304 */  0xE1, 0xF1                                                                  /* lead out */
/*   -, 306 */
};
#define TXN_CUR_A (txn_remit + 233)
#define OTXNACC (txn_remit + 93)
#define HOOKACC (txn_remit + 71)
#define REMIT_FLS (txn_remit + 15)
#define REMIT_LLS (txn_remit + 21)
#define REMIT_FEE (txn_remit + 26)
#define REMIT_EDET (txn_remit + 113)

#define SETHOOK_FLS (txn_sethook + 15)
#define SETHOOK_LLS (txn_sethook + 21)
#define SETHOOK_FEE (txn_sethook + 26)
#define SETHOOK_ACC (txn_sethook + 71)
#define SETHOOK_EMIT (txn_sethook + 91)
#define SETHOOK_NOPS (txn_sethook + 207)
#define SETHOOK_HOOKHASH (txn_sethook + 272)
#define SETHOOK_HOOKON (txn_sethook + 238)

#define EDET_SIZE (116)

#define SET_NATIVE_AMOUNT(ptr, amount)                                         \
  do {                                                                         \
    uint8_t *b = (ptr);                                                        \
    *b++ = 0b01000000 + ((amount >> 56) & 0b00111111);                         \
    *b++ = (amount >> 48) & 0xFFU;                                             \
    *b++ = (amount >> 40) & 0xFFU;                                             \
    *b++ = (amount >> 32) & 0xFFU;                                             \
    *b++ = (amount >> 24) & 0xFFU;                                             \
    *b++ = (amount >> 16) & 0xFFU;                                             \
    *b++ = (amount >> 8) & 0xFFU;                                              \
    *b++ = (amount >> 0) & 0xFFU;                                              \
  } while (0)

#define FLIP_ENDIAN_32(value)                                                  \
  (uint32_t)(((value & 0xFFU) << 24) | ((value & 0xFF00U) << 8) |              \
             ((value & 0xFF0000U) >> 8) | ((value & 0xFF000000U) >> 24))

#define SET_UINT32(ptr, value) *((uint32_t *)(ptr)) = FLIP_ENDIAN_32(value);

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
    uint16_t tt;
    otxn_field(SVAR(tt), sfTransactionType);

    

    if (tt != ttREMIT)
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
        if (slot_count(2) != 1 || slot_subarray(2, 0, 3) != 3) // || slot_subfield(2, sfAmount, 2) != 2)
            NOPE("Top: Remit must contain either one amount (for deposit) or no sfAmounts field (for withdraw).");

        int64_t size = slot(SBUF(amt_buf), 3);
        
        TRACEHEX(amt_buf);
        TRACEVAR(size);

        if (size != 9 && size != 49)
            NOPE("Top: Invalid amount deposited (somehow?) [1].");

         

        // RH UPTO: sub_array doesn't preserve the field type which means slot_type doesn't work properly
        // switch it to a slot dump followed by size test and byte manipulation
        int64_t is_xah = (size == 9);

        TRACEVAR(is_xah);

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

        int64_t amt = float_sto_set(amt_buf, size);

        TRACEVAR(amt);

        if (amt <= 0)
            NOPE("Top: Invalid amount deposited (somehow?) [2].");
        
        if (is_xah)
            amt = float_divide(amt, 6197953087261802496ULL /* 1 MM */);

        TRACEVAR(amt);

        // credit the user
        uint8_t to_key_hash[32];

        TRACEHEX(to_key);
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
        TRACEHEX(to_key_hash);
        TRACEHEX(to_bal_buf);
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

#define IS_EMPTY_20(ptr) (
        *((uint64_t*)(ptr      )) == 0 &&
        *((uint64_t*)(ptr +  8U)) == 0 &&
        *((uint32_t*)(ptr + 16U)) == 0)

    int64_t is_xah = IS_EMPTY_20(req + 21U) && IS_EMPTY_20(req + 41U); // currency and issuer

    TRACEHEX(req);
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

    int64_t bytes = sizeof(txn_remit);

    // if the output is xah then we need to rewrite and shorten the amounts field
    // for the alternative (native) integer format of xah
    if (is_xah)
    {
        int64_t drops = float_int(reqxfl, 6, 0);

        int64_t recalc = float_set(-6, drops);
        TRACEVAR(recalc);
        TRACEVAR(reqxfl); 
        TRACEVAR(drops);

        if (drops <= 0 || float_compare(recalc, reqxfl, COMPARE_GREATER) == 1)
        {
            TRACEVAR(drops);
            NOPE("Top: Insane drops computation.");
        }

        SET_NATIVE_AMOUNT(TXN_CUR_A + 1U, drops);
        bytes -= 40;
        
        *(TXN_CUR_A +  9U) = 0xE1U; // end of object marker
        *(TXN_CUR_A + 10U) = 0xF1U; // end of array marker
    }
    etxn_details(REMIT_EDET, EDET_SIZE);
    SET_NATIVE_AMOUNT(REMIT_FEE, etxn_fee_base(txn_remit, bytes));
    int64_t seq = ledger_seq();
    SET_UINT32(REMIT_FLS, seq + 1);
    SET_UINT32(REMIT_LLS, seq + 5);
    trace(SBUF("emit:"), txn_remit, bytes, 1);
    uint8_t emithash[32];
    int64_t emit_result = emit(SBUF(emithash), txn_remit, bytes);
    if (DEBUG)
        TRACEVAR(emit_result);
    if (emit_result < 0)
        rollback(SBUF("Top: Emit remit failed."), __LINE__);


    // process any pending hooks. do this last because the above could rollback, and we just want to
    // piggyback on a successful txn

    uint8_t hookkey[2] = { 'H', 0 };
    uint8_t hookhash[64];
    int64_t emit_hook = 0;
    uint8_t* nopptr = SETHOOK_NOPS;
    for (hookkey[1] = 0; GUARD(10), hookkey[1] < 10; ++hookkey[1])
    {
        if (state(SBUF(hookhash), SBUF(hookkey)) == 64)
        {
            emit_hook = 1;
            break;
        }

        *nopptr++ = 0xEEU; // hook object start marker
        *nopptr++ = 0xE1U; // end of object marker
    }

    if (!emit_hook)
        DONE("Top: Done.");
        
    // execution to here means we're emitting a hookset

    // set hook on
    COPY32(hookhash + 32U, SETHOOK_HOOKON);

    // set hookhash
    COPY32(hookhash, SETHOOK_HOOKHASH);

    // set from acc
    COPY20(OTXNACC, SETHOOK_ACC);

    // set etxn details
    etxn_details(REMIT_EMIT, EDET_SIZE);

    {
        SET_NATIVE_AMOUNT(SET_HOOK_FEE, etxn_fee_base(SBUF(txn_sethook)));
        int64_t seq = ledger_seq();
        SET_UINT32(SET_HOOK_FLS, seq + 1);
        SET_UINT32(SET_HOOK_LLS, seq + 5);
        trace(SBUF("emitsh:"), SBUF(txn_sethook), 1);
        uint8_t emithash[32];
        int64_t emit_result = emit(SBUF(emithash), SBUF(txn_sethook));
        if (DEBUG)
            TRACEVAR(emit_result);
        if (emit_result < 0)
            rollback(SBUF("Top: Emit sethook failed."), __LINE__);

    }

    // remove the state entry
    state_set(0,0, SBUF(hookkey)); 

    DONE("Top: Done (+sethook)");

    // RHTODO: cbak on failure 
}
