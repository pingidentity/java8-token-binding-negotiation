package temp.random;

import b_c.unbearable.client.TokenBindingMessageMaker;
import b_c.unbearable.messages.TokenBindingKeyParameters;
import b_c.unbearable.utils.EcKeyUtil;
import org.junit.Test;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 *
 */
public class ClientTest
{
    @Test
    public void negoHans() throws Exception {
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true"); //FFS

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null , null);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        sslSocketFactory = new TokenBindingSSLSocketFactory(sslSocketFactory);

        URL url = new URL("https://www.zmartzone.eu:4433/");

        URLConnection urlConnection = url.openConnection();

        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) urlConnection;


        httpsUrlConnection.setSSLSocketFactory(sslSocketFactory);

        httpsUrlConnection.setRequestProperty("Sec-Token-Binding", "AIkAAgBBQBaKc7ww4HVlFLKxCZW8RmttltZ_CvuvHpz5YAR6BCQnbTf3WksAFdBMl6X30JNzJTs4ecIN2aEZUHWGP2Nh0l0AQJqLqBfGRwtzF5OGN0iqOLan-SglWmFePYdxZWvHBLwm9xvzZa2AXwvkYhrby9_asUneLr_TlwYyyRxrrDWQP3oAAA");

        String body = getBody(urlConnection);

        int code = httpsUrlConnection.getResponseCode();
        String msg = httpsUrlConnection.getResponseMessage();

        System.out.println(code + " " + msg + " from " + url);
        System.out.println(body);
    }


    @Test
    public void googNego() throws Exception {
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true"); //FFS

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null , null);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        sslSocketFactory = new TokenBindingSSLSocketFactory(sslSocketFactory);

        URL url = new URL("https://accounts.google.com/ServiceLogin?service=mail&passive=true&rm=false&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&ss=1&scc=1&ltmpl=default&ltmplcache=2&emr=1&osid=1&flowName=GlifWebSignIn&flowEntry=ServiceLogin");

        URLConnection urlConnection = url.openConnection();

        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) urlConnection;


        httpsUrlConnection.setSSLSocketFactory(sslSocketFactory);
        httpsUrlConnection.setInstanceFollowRedirects(false);


        httpsUrlConnection.setRequestProperty("Sec-Token-Binding", "AIkAAgBBQBaKc7ww4HVlFLKxCZW8RmttltZ_CvuvHpz5YAR6BCQnbTf3WksAFdBMl6X30JNzJTs4ecIN2aEZUHWGP2Nh0l0AQJqLqBfGRwtzF5OGN0iqOLan-SglWmFePYdxZWvHBLwm9xvzZa2AXwvkYhrby9_asUneLr_TlwYyyRxrrDWQP3oAAA");


        String charset = getCharset(urlConnection);

        String body = getBody(urlConnection);

        int code = httpsUrlConnection.getResponseCode();
        String msg = httpsUrlConnection.getResponseMessage();

        System.out.println(code + " " + msg + " from " + url);

       // System.out.println(urlConnection.getHeaderField("Location"));
        //System.out.println(body);
    }

    @Test
    public void meh2() throws Exception {
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true"); //FFS needed b/c of Sec- prefix headers aren't set w/ httpsURLConnection.setRequestProperty

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{new OverlyTrustingX509ExtendedTrustManager()} , null);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        TokenBindingSSLSocketFactory tokenBindingSSLSocketFactory = new TokenBindingSSLSocketFactory(sslSocketFactory);


        URL url = new URL("https://localhost:3000/get");
        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection)url.openConnection();
        httpsUrlConnection.setSSLSocketFactory(tokenBindingSSLSocketFactory);
        httpsUrlConnection.connect();
        System.out.println(httpsUrlConnection.getServerCertificates());
        tokenBindingSSLSocketFactory.setSTBHeader(httpsUrlConnection, EcKeyUtil.generateEcP256KeyPair());

        int code = httpsUrlConnection.getResponseCode();
        String msg = httpsUrlConnection.getResponseMessage();
        String body = getBody(httpsUrlConnection);
        System.out.println(code + " " + msg + " from " + url);
        System.out.println(body);

    }

    @Test
    public void localPA() throws Exception {
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true"); //FFS needed b/c of Sec- prefix headers aren't set w/ httpsURLConnection.setRequestProperty

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{new OverlyTrustingX509ExtendedTrustManager()} , null);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        TokenBindingSSLSocketFactory tokenBindingSSLSocketFactory = new TokenBindingSSLSocketFactory(sslSocketFactory);


        URL url = new URL("https://localhost:3000/get");
        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection)url.openConnection();
        httpsUrlConnection.setSSLSocketFactory(tokenBindingSSLSocketFactory);
        String body = getBody(httpsUrlConnection);
        System.out.println(body);

        url = new URL("https://localhost:3000/get");
        httpsUrlConnection = (HttpsURLConnection)url.openConnection();
        httpsUrlConnection.setSSLSocketFactory(tokenBindingSSLSocketFactory);
        tokenBindingSSLSocketFactory.setSTBHeader(httpsUrlConnection, EcKeyUtil.generateEcP256KeyPair());


        body = getBody(httpsUrlConnection);
        int code = httpsUrlConnection.getResponseCode();
        String msg = httpsUrlConnection.getResponseMessage();
        System.out.println(code + " " + msg + " from " + url);
        System.out.println(body);

    }

    @Test
    public void meh() throws Exception {

        int sleepy = 100;

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{new OverlyTrustingX509ExtendedTrustManager()} , null);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        sslSocketFactory = new TokenBindingSSLSocketFactory(sslSocketFactory);

        for (int i = 1; i<10; i++)
        {
            URL url = new URL("https://localhost:3000/get");

            URLConnection urlConnection = url.openConnection();

            HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) urlConnection;


            httpsUrlConnection.setSSLSocketFactory(sslSocketFactory);

            String charset = getCharset(urlConnection);

            String body = getBody(urlConnection);

            int code = httpsUrlConnection.getResponseCode();
            String msg = httpsUrlConnection.getResponseMessage();

            System.out.println(code + " " + msg + " from " + url);

            //System.out.println(body);

            url = new URL("https://localhost:3000/headers");
            url.openConnection();
            urlConnection = url.openConnection();
            httpsUrlConnection = (HttpsURLConnection) urlConnection;
            httpsUrlConnection.setSSLSocketFactory(sslSocketFactory);
            charset = getCharset(urlConnection);
            body = getBody(urlConnection);
            code = httpsUrlConnection.getResponseCode();
            msg = httpsUrlConnection.getResponseMessage();
            System.out.println(code + " " + msg + " from " + url);
            //.out.println(body);

            url = new URL("https://localhost:3000/get?with=this");
            url.openConnection();
            urlConnection = url.openConnection();
            httpsUrlConnection = (HttpsURLConnection) urlConnection;
            httpsUrlConnection.setSSLSocketFactory(sslSocketFactory);
            charset = getCharset(urlConnection);
            body = getBody(urlConnection);
            code = httpsUrlConnection.getResponseCode();
            msg = httpsUrlConnection.getResponseMessage();
            System.out.println(code + " " + msg + " from " + url);
            //System.out.println(body);





            System.out.println("bout to sleep for " + sleepy);
            Thread.sleep(sleepy);
            sleepy = sleepy * 2;
        }
    }

    private String getBody(URLConnection urlConnection) throws IOException
    {
        String charset = getCharset(urlConnection);
        StringWriter writer = new StringWriter();
        try (InputStream is = urlConnection.getInputStream();
             InputStreamReader isr = new InputStreamReader(is, charset))
        {
            char[] buffer = new char[1024];
            int n;
            while (-1 != (n = isr.read(buffer)))
            {
                writer.write(buffer, 0, n);
            }
        }
        return writer.toString();
    }


    String getCharset(URLConnection urlConnection)
    {
        String contentType = urlConnection.getHeaderField("Content-Type");
        String charset = "UTF-8";
        try
        {
            if (contentType != null)
            {
                for (String part : contentType.replace(" ", "").split(";")) {
                    String prefix = "charset=";
                    if (part.startsWith(prefix)) {
                        charset = part.substring(prefix.length());
                        break;
                    }
                }
                Charset.forName(charset);
            }
        }
        catch (Exception e)
        {
            System.out.println("Unexpected problem attempted to determine the charset from the Content-Type ("+contentType+") so will default to using UTF8: " + e);
            charset = "UTF-8";
        }
        return charset;
    }

    static class TokenBindingSSLSocketFactory extends SSLSocketFactory {

        SSLSocketFactory sf;

        SSLSocket sslSocket;

        public TokenBindingSSLSocketFactory(SSLSocketFactory delegate) {
            this.sf = delegate;
        }

        @Override
        public SSLSocket createSocket() throws IOException {
            SSLSocket sslSocket = (SSLSocket) sf.createSocket();
            return configureSocket(sslSocket);
        }

        @Override
        public SSLSocket createSocket(String host, int port) throws IOException {
            SSLSocket sslSocket = (SSLSocket) sf.createSocket(host, port);
            return configureSocket(sslSocket);
        }

        @Override
        public SSLSocket createSocket(
                String host, int port, InetAddress localAddress, int localPort) throws IOException {
            SSLSocket sslSocket = (SSLSocket) sf.createSocket(host, port, localAddress, localPort);
            return configureSocket(sslSocket);
        }

        @Override
        public SSLSocket createSocket(InetAddress host, int port) throws IOException {
            SSLSocket sslSocket = (SSLSocket) sf.createSocket(host, port);
            return configureSocket(sslSocket);
        }

        @Override
        public SSLSocket createSocket(
                InetAddress host, int port, InetAddress localAddress, int localPort) throws IOException {
            SSLSocket sslSocket = (SSLSocket) sf.createSocket(host, port, localAddress, localPort);
            return configureSocket(sslSocket);
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return sf.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return sf.getSupportedCipherSuites();
        }

        @Override
        public SSLSocket createSocket(
                Socket socket, String host, int port, boolean autoClose) throws IOException {
            SSLSocket sslSocket = (SSLSocket) sf.createSocket(socket, host, port, autoClose);
            return configureSocket(sslSocket);
        }

        protected SSLSocket configureSocket(SSLSocket sslSocket) throws IOException {

            System.out.println("configureSocket: " + sslSocket);
            Class<? extends SSLSocket> socketClass = sslSocket.getClass();
            try {
                Method supportedKeyParamsMethod = socketClass.getMethod("setSupportedTokenBindingKeyParams", byte[].class);
                Object supported = new byte[]{2}; //
                supportedKeyParamsMethod.invoke(sslSocket, supported);
            }
            catch (InvocationTargetException | IllegalAccessException e) {
                throw new IOException("Exception thrown by an invoked method on SSLSocket.", e);
            }
            catch (NoSuchMethodException e){
                throw new IOException("No!!!!", e);
            }

            sslSocket.setEnabledProtocols(new String[] {"TLSv1.2"});
            sslSocket.addHandshakeCompletedListener(new MyHandshakeCompletedListener());

            this.sslSocket = sslSocket;

            return sslSocket;
        }

        void setSTBHeader(HttpsURLConnection httpsURLConnection, KeyPair keyPair) throws GeneralSecurityException
        {

            Class<? extends SSLSocket> socketClass = sslSocket.getClass();
            byte[] ekm;
            try {


                Method ekmMethod = socketClass.getMethod("exportKeyingMaterial", String.class, int.class);
                Object invoked = ekmMethod.invoke(sslSocket, "EXPORTER-Token-Binding", 32);
                ekm = (byte[]) invoked;

            }
            catch (InvocationTargetException | IllegalAccessException e) {
                throw new RuntimeException("Exception thrown by an invoked method on SSLSocket.", e);
            }
            catch (NoSuchMethodException e){
                throw new RuntimeException("No!!!!", e);
            }

            TokenBindingMessageMaker maker = new TokenBindingMessageMaker().ekm(ekm).providedTokenBinding(TokenBindingKeyParameters.ECDSAP256, keyPair);
            String tbmsg = maker.makeEncodedTokenBindingMessage();
            httpsURLConnection.setRequestProperty("Sec-Token-Binding", tbmsg);
        }

    }

    static class MyHandshakeCompletedListener implements HandshakeCompletedListener
    {

        @Override
        public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
        {
            SSLSocket socket = handshakeCompletedEvent.getSocket();

            Class<? extends SSLSocket> socketClass = socket.getClass();
            try {
                byte[] ekm;

                Method ekmMethod = socketClass.getMethod("exportKeyingMaterial", String.class, int.class);
                Object invoked = ekmMethod.invoke(socket, "EXPORTER-Token-Binding", 32);
                ekm = (byte[]) invoked;

                System.out.println("************************************************************ EKM: " + Arrays.toString(ekm) + " ************************************************************");

                Method negotiatedTokenBindingKeyParams = socketClass.getMethod("getNegotiatedTokenBindingKeyParams");
                Byte negotiatedKeyParamsId = (Byte)negotiatedTokenBindingKeyParams.invoke(socket);

                System.out.println("getNegotiatedTokenBindingKeyParams: " + negotiatedKeyParamsId);

            }
            catch (InvocationTargetException | IllegalAccessException e) {
                throw new RuntimeException("Exception thrown by an invoked method on SSLSocket.", e);
            }
            catch (NoSuchMethodException e){
                throw new RuntimeException("No!!!!", e);
            }
        }
    }

    static class OverlyTrustingX509ExtendedTrustManager extends X509ExtendedTrustManager
    {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException
        {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException
        {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException
        {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException
        {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException
        {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException
        {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers()
        {
            return new X509Certificate[0];
        }
    }
}
