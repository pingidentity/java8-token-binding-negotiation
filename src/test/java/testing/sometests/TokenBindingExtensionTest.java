package testing.sometests;

import org.junit.Assert;
import org.junit.Test;
import sun.security.ssl.TokenBindingExtension;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import java.util.Arrays;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;
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

        TokenBindingExtension tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PKCS1_5, RSA2048_PSS, ECDSAP256});
        Byte picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PKCS1_5, ECDSAP256});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PSS, ECDSAP256});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {ECDSAP256, RSA2048_PSS, RSA2048_PKCS1_5});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PSS, ECDSAP256, RSA2048_PKCS1_5});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PKCS1_5, ECDSAP256, RSA2048_PSS});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PKCS1_5, ECDSAP256, RSA2048_PSS, 100, 101, 102});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PKCS1_5, RSA2048_PSS, 100, 101, 102, ECDSAP256});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {ECDSAP256, RSA2048_PKCS1_5, RSA2048_PSS, 100, 101, 102, });
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {ECDSAP256});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, new byte[] {-5, 77, 121}); // all unknown
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertNull(picked);

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PSS});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertNull(picked);

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PKCS1_5, RSA2048_PSS});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(RSA2048_PKCS1_5));

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PSS, RSA2048_PKCS1_5});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(RSA2048_PKCS1_5));

        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PSS, 101, 111, RSA2048_PKCS1_5});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(RSA2048_PKCS1_5));

        byte[] keyParams = new byte[256];
        Arrays.fill(keyParams, (byte)111);
        keyParams[0] = RSA2048_PKCS1_5;
        keyParams[keyParams.length-1] = ECDSAP256;
        tbx = new TokenBindingExtension(1, 0, keyParams);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        assertThat(picked, equalTo(ECDSAP256));
    }

    @Test
    public void nullAndEmpty() {
        TokenBindingExtension tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PKCS1_5, RSA2048_PSS, ECDSAP256});
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
        TokenBindingExtension ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        TokenBindingExtension stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 1;
        minor = 1;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 1;
        minor = 7;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 2;
        minor = 0;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 2;
        minor = 1;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 3;
        minor = 0;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 3;
        minor = 0;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(1));
        assertThat(stbx.getMinor(), equalTo(0));

        major = 0;
        minor = 0;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 2;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 8;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 9;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 22;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNull(stbx);

        major = 0;
        minor = 10;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 11;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 12;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 13;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 14;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));

        major = 0;
        minor = 15;
        ctbx = new TokenBindingExtension(major, minor, keyParametersList);
        stbx = TokenBindingExtension.processClientHello(ctbx, true, true, supportedKeyParams);
        assertNotNull(stbx);
        assertThat(stbx.getMajor(), equalTo(major));
        assertThat(stbx.getMinor(), equalTo(minor));
    }


    @Test
    public void clientProcessServerHello() throws SSLException{
        TokenBindingExtension tbx = new TokenBindingExtension(1, 0, ECDSAP256);
        byte negotiated = tbx.processServerHello(true, true, new byte[]{ECDSAP256, RSA2048_PSS, RSA2048_PKCS1_5});
        assertThat(negotiated, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(1, 0, RSA2048_PSS);
        negotiated = tbx.processServerHello(true, true, new byte[]{ECDSAP256, RSA2048_PSS, RSA2048_PKCS1_5});
        assertThat(negotiated, equalTo(RSA2048_PSS));

        tbx = new TokenBindingExtension(1, 0, RSA2048_PKCS1_5);
        negotiated = tbx.processServerHello(true, true, new byte[]{ECDSAP256, RSA2048_PSS, RSA2048_PKCS1_5});
        assertThat(negotiated, equalTo(RSA2048_PKCS1_5));

        tbx = new TokenBindingExtension(1, 0, ECDSAP256);
        negotiated = tbx.processServerHello(true, true, new byte[]{ECDSAP256});
        assertThat(negotiated, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(0, 15, ECDSAP256);
        negotiated = tbx.processServerHello(true, true, new byte[]{ECDSAP256});
        assertThat(negotiated, equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(0, 13, ECDSAP256);
        negotiated = tbx.processServerHello(true, true, new byte[]{ECDSAP256});
        assertThat(negotiated, equalTo(ECDSAP256));

        // version too high
        tbx = new TokenBindingExtension(1, 1, ECDSAP256);
        expectFailOnProcessServerHello(tbx, true, true, new byte[]{ECDSAP256});

        // empty key params
        tbx = new TokenBindingExtension(1, 0, new byte[0]);
        expectFailOnProcessServerHello(tbx, true, true, new byte[]{ECDSAP256});

        // mismatched key params
        tbx = new TokenBindingExtension(1, 0, RSA2048_PSS);
        expectFailOnProcessServerHello(tbx, true, true, new byte[]{ECDSAP256});

        // unknown & mismatched key params
        tbx = new TokenBindingExtension(1, 0, (byte)9);
        expectFailOnProcessServerHello(tbx, true, true, new byte[]{ECDSAP256, RSA2048_PSS, RSA2048_PKCS1_5});

        // too many key params
        tbx = new TokenBindingExtension(1, 0, new byte[] {RSA2048_PSS, ECDSAP256});
        expectFailOnProcessServerHello(tbx, true, true, new byte[]{ECDSAP256});

        // no extended master
        tbx = new TokenBindingExtension(1, 0, ECDSAP256);
        expectFailOnProcessServerHello(tbx, false, true, new byte[]{ECDSAP256});

        // no secureRenegotiation
        expectFailOnProcessServerHello(tbx, true, false, new byte[]{ECDSAP256});

        // neither
        expectFailOnProcessServerHello(tbx, false, false, new byte[]{ECDSAP256});

    }

    void expectFailOnProcessServerHello(TokenBindingExtension tbx, boolean isExtendedMaster, boolean secureRenegotiation, byte[] requestedKeyParamsList) {
        try {
            byte negotiated = tbx.processServerHello(isExtendedMaster, secureRenegotiation, requestedKeyParamsList);
            fail("processServerHello should have thrown exception but returned " + negotiated);
        }
        catch (SSLHandshakeException e) {
            // expected
            //System.out.println(e);
        }
    }

    @Test
    public void testSimpleDelimitedKeyParamsString() {
        Assert.assertArrayEquals(TokenBindingExtension.parseKeyParamsList("0,1,2"), new byte[] {0,1,2});
        Assert.assertArrayEquals(TokenBindingExtension.parseKeyParamsList(" 0, 1, 2   "), new byte[] {0,1,2});
        Assert.assertArrayEquals(TokenBindingExtension.parseKeyParamsList("0, 1 , 2"), new byte[] {0,1,2});
        Assert.assertArrayEquals(TokenBindingExtension.parseKeyParamsList("2"), new byte[] {2});
        Assert.assertArrayEquals(TokenBindingExtension.parseKeyParamsList("2,0"), new byte[] {2,0});
        Assert.assertArrayEquals(TokenBindingExtension.parseKeyParamsList("2, 0"), new byte[] {2,0});
    }
}
