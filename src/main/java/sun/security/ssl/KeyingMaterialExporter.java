/*
 * Copyright (c) 2017, Ping Identity Corp. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Ping Identity designates this
 * particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 */
// -- token binding etc. changes begin --
package sun.security.ssl;

import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;

/**
 *
 */
public class KeyingMaterialExporter
{
    static byte[] ekm(String label,
                      int length,
                      ProtocolVersion protocolVersion,
                      SSLSessionImpl sess,
                      byte[] clientRandom,
                      byte[] serverRandom)
            throws DigestException, NoSuchAlgorithmException
    {
        byte[] rawMaster = sess.getMasterSecret().getEncoded();
        byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
        byte[] seed = TlsPrf.concat(clientRandom, serverRandom);
        if (protocolVersion.v == 0x0303) {
            CipherSuite.PRF prfAlg = sess.getSuite().prfAlg;
            return TlsPrf.doTLS12PRF(rawMaster, labelBytes, seed, length,
                    prfAlg.getPRFHashAlg(), prfAlg.getPRFHashLength(), prfAlg.getPRFBlockSize());
        } else if (protocolVersion.v == 0x0302 || protocolVersion.v == 0x0301 ) {
            return TlsPrf.doTLS10PRF(rawMaster, labelBytes, seed, length);
        } else {
            throw new IllegalStateException("EKM not supported for version " + protocolVersion);
        }
    }
}
// -- token binding etc. changes end --