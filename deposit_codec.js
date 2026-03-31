const makeDeposit = (
    social_network_id,   /* 0 - 255 */
    user_id_to           /* 0 - 18,446,744,073,709,551,615, or 20 bytes of xahau acc id in HEX */
) => 
{
    const checkInteger = (inttocheck, intmin, intmax, intname) =>
    {
        if (typeof(inttocheck) != 'number' ||
            inttocheck < intmin || inttocheck > intmax || 
            Math.floor(inttocheck) != inttocheck)
            throw new Error(intname + " must be an integer between " + intmin + " and " + intmax);
    };

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

    checkInteger(social_network_id, 0, 255, "social_network_id");

    checkInteger(user_id_to, 0, 2**64-1, "user_id_to");

    let out = '';

    out += makeLEHex(social_network_id, 2);
    
    out += '0'.repeat(24);
    out += makeLEHex(user_id_to, 16);

    return out;
};
