package sun.security.ssl;

import java.io.IOException;

/**
 *
 */
public class ExtendedMasterSecretExtension extends HelloExtension
{
    static final byte[] ENTIRE_EXTENSION_ENCODING = new byte[] {0x00, 0x17, 0x00, 0x00};
    static final int ID = ENTIRE_EXTENSION_ENCODING[1];

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