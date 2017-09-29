package sun.security.ssl;

import java.io.IOException;
import java.util.Arrays;

/**
 *
 */
public class TokenBindingExtension extends HelloExtension
{
    static final byte[] EMPTY = new byte[0];

    static final byte RSA2048_PKCS1_5 = 0;
    static final byte RSA2048_PSS = 1;
    static final byte ECDSAP256 = 2;

    static final int ID = 24;

    int major;
    int minor;

    byte[] keyParametersList;

    TokenBindingExtension(HandshakeInStream handshakeInStream, ExtensionType extensionType) throws IOException {
        super(extensionType);
        major = handshakeInStream.getInt8();
        minor = handshakeInStream.getInt8();
        keyParametersList = handshakeInStream.getBytes8();
    }

    TokenBindingExtension(int major, int minor, byte keyParameter) {
        super(ExtensionType.EXT_TOKEN_BINDING);
        this.major = major;
        this.minor = minor;
        this.keyParametersList = new byte[] {keyParameter};
    }

    public TokenBindingExtension(byte[] keyParametersList, int major, int minor) {
        super(ExtensionType.EXT_TOKEN_BINDING);
        this.major = major;
        this.minor = minor;
        this.keyParametersList = keyParametersList;
    }

    public static TokenBindingExtension forServerHello(HelloExtension clientTbx, boolean isExtendedMaster, boolean secureRenegotiation, byte[] supportedKeyParams) {
        if (clientTbx != null && isExtendedMaster & (secureRenegotiation || Handshaker.rejectClientInitiatedRenego)) {
            TokenBindingExtension tbx = (TokenBindingExtension) clientTbx;
            boolean isDraftVersion = tbx.major == 0;
            if (tbx.major >= 1 || (isDraftVersion && (tbx.minor >= 10 && tbx.minor <= 15))) {  // drafts -10 through -15 should be message format compatible with 1.0
                Byte chosenKeyParameter = tbx.pickKeyParameter(supportedKeyParams);
                if (chosenKeyParameter != null) {
                    int major = isDraftVersion ? tbx.major : 1;
                    int minor = isDraftVersion ? tbx.minor : 0;
                    return new TokenBindingExtension(major, minor, chosenKeyParameter);
                }
            }
        }
        return null;
    }

    public Byte pickKeyParameter(byte[] supportedKeyParams) {

        supportedKeyParams = supportedKeyParams == null ? EMPTY : supportedKeyParams;

        int chosenIdx = supportedKeyParams.length;

        for (byte clientKeyParam : keyParametersList) {
            for (int idx = 0; idx < chosenIdx; idx++) {
                if (clientKeyParam == supportedKeyParams[idx]) {
                    chosenIdx = (idx < chosenIdx) ? idx : chosenIdx;
                }
            }
        }

        return chosenIdx < supportedKeyParams.length ? supportedKeyParams[chosenIdx] : null;
    }

    public int getMajor()
    {
        return major;
    }

    public int getMinor()
    {
        return minor;
    }

    @Override
    int length() {
        // Length of the encoded extension, including the type (2) and length (2) fields
        return 2 + 2 + rawLength();
    }

    int rawLength() {
        // major + minor + length of key parameters list + key parameters list
        return 1 + 1 + 1 + keyParametersList.length;
    }

    @Override
    void send(HandshakeOutStream s) throws IOException {
        s.putInt16(type.id);
        s.putInt16(rawLength());
        s.putInt8(major);
        s.putInt8(minor);
        s.putBytes8(keyParametersList);
    }

    @Override
    public String toString() {
        return String.format("Extension %s v%s.%s w/ %s", type, major, minor, Arrays.toString(keyParametersList));
    }

}