package sun.security.ssl;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

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

        TokenBindingExtension tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, RSA2048_PSS, ECDSAP256});
        Byte picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, ECDSAP256});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS, ECDSAP256});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {ECDSAP256, RSA2048_PSS, RSA2048_PKCS1_5});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS, ECDSAP256, RSA2048_PKCS1_5});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, ECDSAP256, RSA2048_PSS});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, ECDSAP256, RSA2048_PSS, 100, 101, 102});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, RSA2048_PSS, 100, 101, 102, ECDSAP256});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {ECDSAP256, RSA2048_PKCS1_5, RSA2048_PSS, 100, 101, 102, });
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {ECDSAP256});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));

        tbx = new TokenBindingExtension(new byte[] {-5, 77, 121}); // all unknown
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertNull(picked);

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertNull(picked);

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, RSA2048_PSS});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(RSA2048_PKCS1_5));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS, RSA2048_PKCS1_5});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(RSA2048_PKCS1_5));

        tbx = new TokenBindingExtension(new byte[] {RSA2048_PSS, 101, 111, RSA2048_PKCS1_5});
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(RSA2048_PKCS1_5));

        byte[] keyParams = new byte[256];
        Arrays.fill(keyParams, (byte)111);
        keyParams[0] = RSA2048_PKCS1_5;
        keyParams[keyParams.length-1] = ECDSAP256;
        tbx = new TokenBindingExtension(keyParams);
        picked = tbx.pickKeyParameter(supportedKeyParams);
        Assert.assertThat(picked, CoreMatchers.equalTo(ECDSAP256));
    }

    @Test
    public void nullAndEmpty() {
        TokenBindingExtension tbx = new TokenBindingExtension(new byte[] {RSA2048_PKCS1_5, RSA2048_PSS, ECDSAP256});
        Byte picked = tbx.pickKeyParameter(new byte[0]);
        Assert.assertNull(picked);

        picked = tbx.pickKeyParameter(null);
        Assert.assertNull(picked);
    }
}
