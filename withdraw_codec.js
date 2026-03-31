const makeWithdraw = (
    currency_code,       /* 0 for xah, or 20 bytes of currency code in HEX */
    issuer_acc_id,       /* 0 for xah, or 20 bytes of issuer xahau account id in HEX */
    amount_tipped       /* a floating point amount that was tipped */
) => 
{
    const checkHex = (hextocheck, hexsize, hexname) =>
    {
        if (typeof(hextocheck) != 'string' ||
            hextocheck.length != hexsize ||
            !/^[0-9a-fA-F]+$/.test(hextocheck))
            throw new Error(hexname + " must be a hex string of exactly " + hexsize + " characters");
    };

    const makeLEHex = (num, field_len_nibbles) =>
    {
        let tmp = num.toString(16);
        if (tmp.length % 2 == 1)
            tmp = '0' + tmp;
        tmp = tmp.toUpperCase();

        let fin = '';
        for (let i = tmp.length - 2; i >= 0; i-=2)
            fin += tmp.slice(i, i + 2);

        let pad = field_len_nibbles - fin.length;
        if (pad > 0)
            fin += '0'.repeat(pad);

        return fin;
    }

    const makeLEXFLHex = (num, field_len_nibbles) =>
    {
        const MIN_MANTISSA = 1000000000000000n;
        const MAX_MANTISSA = 9999999999999999n;
        const MIN_EXP = -96;
        const MAX_EXP = 80;

        function makeXfl(exp, man) {
            if (typeof exp !== 'bigint') exp = BigInt(exp);
            if (typeof man !== 'bigint') man = BigInt(man);
            if (man === 0n) return 0n;

            const neg = man < 0n;
            if (neg) man = -man;

            while (man > MAX_MANTISSA) { man /= 10n; exp++; }
            while (man < MIN_MANTISSA) { man *= 10n; exp--; }

            if (exp > MAX_EXP || exp < MIN_EXP) return -1n;

            let xfl = neg ? 0n : 1n;
            xfl = (xfl << 8n) | (BigInt(exp) + 97n);
            xfl = (xfl << 54n) | man;
            return xfl;
        }

        // Parse a JS number into XFL bigint
        let d = String(parseFloat(String(num))).toLowerCase();
        let e = 0;
        let s = d.split('e');
        if (s.length === 2) { e = parseInt(s[1]); d = s[0]; }
        s = d.split('.');
        if (s.length === 2) { d = d.replace('.', ''); e -= s[1].length; }

        const xfl = makeXfl(e, d);
        if (xfl < 0n) throw new Error(`Cannot encode ${num} as XFL`);

        // Encode as little-endian hex
        const be = xfl.toString(16).padStart(16, '0');
        let le = '';
        for (let i = 14; i >= 0; i -= 2) le += be.slice(i, i + 2);

        // Pad with trailing zeros (high bytes) to reach desired nibble length
        if (field_len_nibbles % 2 !== 0) throw new Error('field_len_nibbles must be even');
        if (field_len_nibbles < 16) throw new Error('field_len_nibbles must be >= 16 (XFL is 8 bytes)');
        return le.padEnd(field_len_nibbles, '0').toUpperCase();
    }

    if (typeof(currency_code) == 'string')
        checkHex(currency_code, 40, "currency_code")
    else if (typeof(currency_code) != 'number' || currency_code != 0)
        throw new Error("currency_code must be either 0 or a 20 byte account id in HEX");


    if (typeof(issuer_acc_id) == 'string')
        checkHex(issuer_acc_id, 40, "issuer_acc_id")
    else if (typeof(issuer_acc_id) != 'number' || issuer_acc_id != 0)
        throw new Error("issuer_acc_id must be either 0 or a 20 byte account id in HEX");

    if (typeof(amount_tipped) != 'number' || amount_tipped <= 0)
        throw new Error("amount_tipped must be a positive number");

    // execution to here means inputs are well formed

    let out = '';

    if (currency_code == 0)
        out += '0'.repeat(40)
    else
        out += currency_code.toUpperCase();

    if (issuer_acc_id == 0)
        out += '0'.repeat(40)
    else
        out += issuer_acc_id.toUpperCase();

    out += makeLEXFLHex(amount_tipped, 16);

    return out;
};
