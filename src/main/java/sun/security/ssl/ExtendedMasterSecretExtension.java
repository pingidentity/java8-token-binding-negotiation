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

import java.io.IOException;

/**
 *
 */
public class ExtendedMasterSecretExtension extends HelloExtension
{
    static final byte[] ENTIRE_EXTENSION_ENCODING = new byte[] {0x00, 0x17, 0x00, 0x00};
    static final int ID = ENTIRE_EXTENSION_ENCODING[1];

    ExtendedMasterSecretExtension()
    {
        super(ExtensionType.EXT_EXTENDED_MASTER_SECRET);
    }

    ExtendedMasterSecretExtension(int len, ExtensionType extensionType) throws IOException {
        super(extensionType);
        if (len != 0) {
            throw new IOException("The extension_data field of the extended_master_secret extension is not empty");
        }
    }

    @Override
    int length() {
        return ENTIRE_EXTENSION_ENCODING.length;
    }


    @Override
    void send(HandshakeOutStream s) throws IOException {
        s.write(ENTIRE_EXTENSION_ENCODING);
    }

    @Override
    public String toString() {
        return String.format("Extension " + type);
    }

}
// -- token binding etc. changes end --