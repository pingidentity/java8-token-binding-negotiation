package sun.security.ssl;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * some bits of TlsPrfGenerator
 */
public class TlsPrf {

    /*
     * TLS HMAC "inner" and "outer" padding.  This isn't a function
     * of the digest algorithm.
     */
    private static final byte[] HMAC_ipad64  = genPad((byte)0x36, 64);
    private static final byte[] HMAC_ipad128 = genPad((byte)0x36, 128);
    private static final byte[] HMAC_opad64  = genPad((byte)0x5c, 64);
    private static final byte[] HMAC_opad128 = genPad((byte)0x5c, 128);

    private final static byte[] B0 = new byte[0];

    static byte[] doTLS12PRF(byte[] secret, byte[] labelBytes,
                             byte[] seed, int outputLength,
                             String prfHash, int prfHashLength, int prfBlockSize)
            throws NoSuchAlgorithmException, DigestException
    {
        if (prfHash == null) {
            throw new NoSuchAlgorithmException("Unspecified PRF algorithm");
        }
        MessageDigest prfMD = MessageDigest.getInstance(prfHash);
        return doTLS12PRF(secret, labelBytes, seed, outputLength,
                prfMD, prfHashLength, prfBlockSize);
    }

    static byte[] doTLS12PRF(byte[] secret, byte[] labelBytes,
                             byte[] seed, int outputLength,
                             MessageDigest mdPRF, int mdPRFLen, int mdPRFBlockSize)
            throws DigestException {

        if (secret == null) {
            secret = B0;
        }

        // If we have a long secret, digest it first.
        if (secret.length > mdPRFBlockSize) {
            secret = mdPRF.digest(secret);
        }

        byte[] output = new byte[outputLength];
        byte [] ipad;
        byte [] opad;

        switch (mdPRFBlockSize) {
            case 64:
                ipad = HMAC_ipad64.clone();
                opad = HMAC_opad64.clone();
                break;
            case 128:
                ipad = HMAC_ipad128.clone();
                opad = HMAC_opad128.clone();
                break;
            default:
                throw new DigestException("Unexpected block size.");
        }

        // P_HASH(Secret, label + seed)
        expand(mdPRF, mdPRFLen, secret, 0, secret.length, labelBytes,
                seed, output, ipad, opad);

        return output;
    }

    static byte[] doTLS10PRF(byte[] secret, byte[] labelBytes,
                            byte[] seed, int outputLength) throws NoSuchAlgorithmException,
            DigestException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha = MessageDigest.getInstance("SHA1");
        return doTLS10PRF(secret, labelBytes, seed, outputLength, md5, sha);
    }

    static byte[] doTLS10PRF(byte[] secret, byte[] labelBytes,
                             byte[] seed, int outputLength, MessageDigest md5,
                             MessageDigest sha) throws DigestException {
        /*
         * Split the secret into two halves S1 and S2 of same length.
         * S1 is taken from the first half of the secret, S2 from the
         * second half.
         * Their length is created by rounding up the length of the
         * overall secret divided by two; thus, if the original secret
         * is an odd number of bytes long, the last byte of S1 will be
         * the same as the first byte of S2.
         *
         * Note: Instead of creating S1 and S2, we determine the offset into
         * the overall secret where S2 starts.
         */

        if (secret == null) {
            secret = B0;
        }
        int off = secret.length >> 1;
        int seclen = off + (secret.length & 1);

        byte[] secKey = secret;
        int keyLen = seclen;
        byte[] output = new byte[outputLength];

        // P_MD5(S1, label + seed)
        // If we have a long secret, digest it first.
        if (seclen > 64) {              // 64: block size of HMAC-MD5
            md5.update(secret, 0, seclen);
            secKey = md5.digest();
            keyLen = secKey.length;
        }
        expand(md5, 16, secKey, 0, keyLen, labelBytes, seed, output,
                HMAC_ipad64.clone(), HMAC_opad64.clone());

        // P_SHA-1(S2, label + seed)
        // If we have a long secret, digest it first.
        if (seclen > 64) {              // 64: block size of HMAC-SHA1
            sha.update(secret, off, seclen);
            secKey = sha.digest();
            keyLen = secKey.length;
            off = 0;
        }
        expand(sha, 20, secKey, off, keyLen, labelBytes, seed, output,
                HMAC_ipad64.clone(), HMAC_opad64.clone());

        return output;
    }

    static byte[] genPad(byte b, int count) {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }

    static byte[] concat(byte[] b1, byte[] b2) {
        int n1 = b1.length;
        int n2 = b2.length;
        byte[] b = new byte[n1 + n2];
        System.arraycopy(b1, 0, b, 0, n1);
        System.arraycopy(b2, 0, b, n1, n2);
        return b;
    }

    /*
    * @param digest the MessageDigest to produce the HMAC
    * @param hmacSize the HMAC size
    * @param secret the secret
    * @param secOff the offset into the secret
    * @param secLen the secret length
    * @param label the label
    * @param seed the seed
    * @param output the output array
    */
    private static void expand(MessageDigest digest, int hmacSize,
                               byte[] secret, int secOff, int secLen, byte[] label, byte[] seed,
                               byte[] output, byte[] pad1, byte[] pad2) throws DigestException {
        /*
         * modify the padding used, by XORing the key into our copy of that
         * padding.  That's to avoid doing that for each HMAC computation.
         */
        for (int i = 0; i < secLen; i++) {
            pad1[i] ^= secret[i + secOff];
            pad2[i] ^= secret[i + secOff];
        }

        byte[] tmp = new byte[hmacSize];
        byte[] aBytes = null;

        /*
         * compute:
         *
         *     P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
         *                            HMAC_hash(secret, A(2) + seed) +
         *                            HMAC_hash(secret, A(3) + seed) + ...
         * A() is defined as:
         *
         *     A(0) = seed
         *     A(i) = HMAC_hash(secret, A(i-1))
         */
        int remaining = output.length;
        int ofs = 0;
        while (remaining > 0) {
            /*
             * compute A() ...
             */
            // inner digest
            digest.update(pad1);
            if (aBytes == null) {
                digest.update(label);
                digest.update(seed);
            } else {
                digest.update(aBytes);
            }
            digest.digest(tmp, 0, hmacSize);

            // outer digest
            digest.update(pad2);
            digest.update(tmp);
            if (aBytes == null) {
                aBytes = new byte[hmacSize];
            }
            digest.digest(aBytes, 0, hmacSize);

            /*
             * compute HMAC_hash() ...
             */
            // inner digest
            digest.update(pad1);
            digest.update(aBytes);
            digest.update(label);
            digest.update(seed);
            digest.digest(tmp, 0, hmacSize);

            // outer digest
            digest.update(pad2);
            digest.update(tmp);
            digest.digest(tmp, 0, hmacSize);

            int k = Math.min(hmacSize, remaining);
            for (int i = 0; i < k; i++) {
                output[ofs++] ^= tmp[i];
            }
            remaining -= k;
        }
    }
}
