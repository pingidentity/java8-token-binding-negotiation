/*
 * Copyright (c) 2005, 2011, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package sun.security.ssl;

import java.security.*;

import javax.crypto.*;

import sun.security.internal.interfaces.TlsMasterSecret;
import sun.security.internal.spec.TlsMasterSecretParameterSpec;


/**
 * Modified from com.sun.crypto.provider.TlsMasterSecretGenerator
 * to do the TLS extended master secret (RFC 7627) derivation.
 */
public final class ExtendedMasterSecretGenerator {


    final static byte[] LABEL_EXTENDED_MASTER_SECRET =  //  "extended master secret"
            {101, 120, 116, 101, 110, 100, 101, 100, 32, 109, 97,
             115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};


    private TlsMasterSecretParameterSpec spec;

    private int protocolVersion;

    public ExtendedMasterSecretGenerator() {
    }

    protected void init(TlsMasterSecretParameterSpec params)
            throws InvalidAlgorithmParameterException {

        this.spec = params;

        if (!"RAW".equals(spec.getPremasterSecret().getFormat())) {
            throw new InvalidAlgorithmParameterException(
                    "Key format must be RAW");
        }
        protocolVersion = (spec.getMajorVersion() << 8)
                | spec.getMinorVersion();
        if ((protocolVersion < 0x0301) || (protocolVersion > 0x0303)) {
            throw new InvalidAlgorithmParameterException(
                    "Only TLS 1.0/1.1/1.2 supported");
        }
    }

    protected SecretKey generateKey() {
        if (spec == null) {
            throw new IllegalStateException(
                    "TlsMasterSecretGenerator must be initialized");
        }
        SecretKey premasterKey = spec.getPremasterSecret();
        byte[] premaster = premasterKey.getEncoded();

        int premasterMajor, premasterMinor;
        if (premasterKey.getAlgorithm().equals("TlsRsaPremasterSecret")) {
            // RSA
            premasterMajor = premaster[0] & 0xff;
            premasterMinor = premaster[1] & 0xff;
        } else {
            // DH, KRB5, others
            premasterMajor = -1;
            premasterMinor = -1;
        }

        try {
            byte[] master;
            byte[] clientRandom = spec.getClientRandom();
            byte[] serverRandom = spec.getServerRandom();

            if (protocolVersion >= 0x0301) {
                byte[] seed = TlsPrf.concat(clientRandom, serverRandom);
                master = ((protocolVersion >= 0x0303) ?
                        TlsPrf.doTLS12PRF(premaster, LABEL_EXTENDED_MASTER_SECRET, seed, 48,
                                spec.getPRFHashAlg(), spec.getPRFHashLength(),
                                spec.getPRFBlockSize()) :
                        TlsPrf.doTLS10PRF(premaster, LABEL_EXTENDED_MASTER_SECRET, seed, 48));
            } else {
                throw new ProviderException("Extended master secret is only supported with TLS (not SSL).");
            }

            return new TlsExtendedMasterSecretKey(master, premasterMajor,
                    premasterMinor);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        } catch (DigestException e) {
            throw new ProviderException(e);
        }
    }

    private static final class TlsExtendedMasterSecretKey implements TlsMasterSecret {
        private static final long serialVersionUID = 1019571680375368880L;

        private byte[] key;
        private final int majorVersion, minorVersion;

        TlsExtendedMasterSecretKey(byte[] key, int majorVersion, int minorVersion) {
            this.key = key;
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
        }

        public int getMajorVersion() {
            return majorVersion;
        }

        public int getMinorVersion() {
            return minorVersion;
        }

        public String getAlgorithm() {
            return "TlsMasterSecret";
        }

        public String getFormat() {
            return "RAW";
        }

        public byte[] getEncoded() {
            return key.clone();
        }

    }

}
