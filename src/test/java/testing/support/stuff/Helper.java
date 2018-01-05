package testing.support.stuff;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.util.Base64;

/**
 *
 */
public class Helper {

    public static final String SEND_EKM = "SHOW ME THE EKM!";

    static public KeyManager[] loadKeyManager(String password, String filename) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        char[] pwd = password.toCharArray();
        ClassLoader classLoader = Helper.class.getClassLoader();

        try (InputStream resourceAsStream = classLoader.getResourceAsStream(filename)) {
            keyStore.load(resourceAsStream, pwd);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        kmf.init(keyStore, pwd);
        return kmf.getKeyManagers();
    }

    static public TrustManager[] loadTrustManagers(String password, String filename) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        ClassLoader classLoader = Helper.class.getClassLoader();

        try (InputStream resourceAsStream = classLoader.getResourceAsStream(filename)) {
            trustStore.load(resourceAsStream, password.toCharArray());
        }

        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);
        return trustFactory.getTrustManagers();
    }

    static public Byte getNegotiatedTokenBindingKeyParams(Object object) throws ReflectiveOperationException {
        Method tbKeyParamsMethod = object.getClass().getMethod("getNegotiatedTokenBindingKeyParams");
        return (Byte)tbKeyParamsMethod.invoke(object);
    }

    static public void setSupportedTokenBindingKeyParams(Object object, byte[] supported) throws ReflectiveOperationException {
        Method supportedKeyParamsMethod = object.getClass().getMethod("setSupportedTokenBindingKeyParams", byte[].class);
        supportedKeyParamsMethod.invoke(object, (Object) supported);
    }

    static public String getEncodedTokenBindingEKM(Object object) throws ReflectiveOperationException {
        Method ekmMethod = object.getClass().getMethod("exportKeyingMaterial", String.class, int.class);
        Object invoked = ekmMethod.invoke(object, "EXPORTER-Token-Binding", 32);
        byte[] ekm = (byte[]) invoked;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(ekm);
    }

}
