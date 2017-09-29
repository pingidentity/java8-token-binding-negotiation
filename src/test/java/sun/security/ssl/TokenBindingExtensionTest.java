package sun.security.ssl;

import org.junit.Test;

import java.util.Arrays;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static sun.security.ssl.TokenBindingExtension.ECDSAP256;
import static sun.security.ssl.TokenBindingExtension.RSA2048_PKCS1_5;
import static sun.security.ssl.TokenBindingExtension.RSA2048_PSS;

/**
 * 
 */
public class TokenBindingExtensionTest {
    @Test
    public void pickKeyParameterDefaultTest() {
        byte[] supportedKeyParams = new byte[] {ECDSAP256, RSA2048_PKCS1_5};

        TokenBindingExtension tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, RSA2048_PSS, ECDSAP256}, 1, 0);
        Byte picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, ECDSAP256}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS, ECDSAP256}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {ECDSAP256, RSA2048_PSS, RSA2048_PKCS1_5}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS, ECDSAP256, RSA2048_PKCS1_5}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, ECDSAP256, RSA2048_PSS}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, ECDSAP256, RSA2048_PSS, 100, 101, 102}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, RSA2048_PSS, 100, 101, 102, ECDSAP256}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {ECDSAP256, RSA2048_PKCS1_5, RSA2048_PSS, 100, 101, 102, }, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {ECDSAP256}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {-5, 77, 121}, 1, 0); // all unknown
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertNull(picked);

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertNull(picked);

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, RSA2048_PSS}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(RSA2048_PKCS1_5));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS, RSA2048_PKCS1_5}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(RSA2048_PKCS1_5));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS, 101, 111, RSA2048_PKCS1_5}, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(RSA2048_PKCS1_5));

        byte[] keyParams = new byte[256];
        Arrays.fill(keyParams, (byte)111);
        keyParams[0] = RSA2048_PKCS1_5;
        keyParams[keyParams.length-1] = ECDSAP256;
        tbx = new TokenBindingExtension(keyParams, 1, 0);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));
    }

    @Test
    public void nullAndEmpty() {
        TokenBindingExtension tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, RSA2048_PSS, ECDSAP256}, 1, 0);
        Byte picked = tbx.pickKeyParameter(new byte[0]);
        assertNull(picked);

        picked = tbx.pickKeyParameter(null);
        assertNull(picked);
    }

    @Test
    public void versionNegotiation() {
        byte[] keyParametersList = {ECDSAP256};
        byte[] supportedKeyParams = {ECDSAP256, RSA2048_PKCS1_5, RSA2048_PSS};

        int major = 1;
        int minor = 0;
        TokenBindingExtension ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        TokenBindingExtension stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 1;
        minor = 1;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 1;
        minor = 7;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 2;
        minor = 0;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 2;
        minor = 1;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 3;
        minor = 0;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 3;
        minor = 0;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 0;
        minor = 0;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 2;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 8;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 9;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 22;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 10;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 11;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 12;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 13;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 14;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 15;
        ctbx = new TokenBindingExtension(keyParametersList, major, minor);
        stbx = TokenBindingExtension.forServerHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));
    }

}
