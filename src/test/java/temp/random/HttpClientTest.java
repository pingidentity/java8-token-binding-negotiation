package temp.random;

import b_c.unbearable.client.TokenBindingMessageMaker;
import b_c.unbearable.messages.TokenBindingKeyParameters;
import b_c.unbearable.utils.EcKeyUtil;
import org.apache.http.Consts;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ConnectionRequest;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 *
 */
public class HttpClientTest
{
    static String tokenBindingHeader;
    static KeyPair keyPair;

    static {
        try
        {
            keyPair = EcKeyUtil.generateEcP256KeyPair();
        }
        catch (GeneralSecurityException e)
        {
            e.printStackTrace();
        }
    }

    @Test
    public void meh2() throws Exception {



        SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(new OverlyTrustingTrustStrategy()).build();

        LayeredConnectionSocketFactory sslsf = new TokenBindingSSLConnectionSocketFactory(sslContext);
        Registry<ConnectionSocketFactory> r = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", sslsf)
                .build();

        BasicHttpClientConnectionManager connManager = new BasicHttpClientConnectionManager(r);
        CloseableHttpClient httpclient = HttpClients.custom()
                .setConnectionManager(connManager)
                .addInterceptorLast(new HttpRequestInterceptor() {
                    public void process(final HttpRequest request, final HttpContext context) throws HttpException, IOException {
                        request.addHeader("User-Agent", "whatevs");
                        System.out.println("in HttpRequestInterceptor");
                        request.addHeader("Sec-Token-Binding", tokenBindingHeader);
                    }
                })
                .build();

        HttpClientContext context = HttpClientContext.create();

        HttpHost target = new HttpHost("localhost", 3000, "https");
        HttpRoute route = new HttpRoute(target, null, true);
        ConnectionRequest connectionRequest = connManager.requestConnection(route, null);
        HttpClientConnection httpClientConnection = connectionRequest.get(10, TimeUnit.SECONDS);
        connManager.connect(httpClientConnection, route, 10000, context);
        connManager.releaseConnection(httpClientConnection, null, 1, TimeUnit.MINUTES);
        System.out.println("now w/ tb msg? " + tokenBindingHeader );

        HttpGet httpGet = new HttpGet("https://localhost:3000/get");
        CloseableHttpResponse response1 = httpclient.execute(httpGet, context);
        // The underlying HTTP connection is still held by the response object
        // to allow the response content to be streamed directly from the network socket.
        // In order to ensure correct deallocation of system resources
        // the user MUST call CloseableHttpResponse#close() from a finally clause.
        // Please note that if response content is not fully consumed the underlying
        // connection cannot be safely re-used and will be shut down and discarded
        // by the connection manager.
        try {
            System.out.println(response1.getStatusLine());
            
            HttpEntity entity1 = response1.getEntity();
            // do something useful with the response body
            // and ensure it is fully consumed
            String s = EntityUtils.toString(entity1);
            System.out.println(s);
        } finally {
            response1.close();
        }

        HttpGet httpGet2 = new HttpGet("https://localhost:3000/headers");
        CloseableHttpResponse response2 = httpclient.execute(httpGet2, context);
        // The underlying HTTP connection is still held by the response object
        // to allow the response content to be streamed directly from the network socket.
        // In order to ensure correct deallocation of system resources
        // the user MUST call CloseableHttpResponse#close() from a finally clause.
        // Please note that if response content is not fully consumed the underlying
        // connection cannot be safely re-used and will be shut down and discarded
        // by the connection manager.
        try {
            System.out.println(response2.getStatusLine());

            HttpEntity entity2 = response2.getEntity();
            // do something useful with the response body
            // and ensure it is fully consumed
            String s = EntityUtils.toString(entity2);
            System.out.println(s);
        } finally {
            response1.close();
        }

    }


    static class TokenBindingSSLConnectionSocketFactory extends SSLConnectionSocketFactory {

        public TokenBindingSSLConnectionSocketFactory(SSLContext sslContext) {
            super(sslContext);
        }

        @Override
        public Socket connectSocket(int connectTimeout, Socket socket, HttpHost host, InetSocketAddress remoteAddress, InetSocketAddress localAddress, HttpContext context) throws IOException
        {
            System.out.println("calling connectSocket " + socket);
            Socket connectedSocket = super.connectSocket(connectTimeout, socket, host, remoteAddress, localAddress, context);
            System.out.println("returned from connectSocket " + connectedSocket);
            System.out.println(" connectSocket getSoTimeout" + connectedSocket.getSoTimeout());

            return connectedSocket;
        }

        @Override
        protected void prepareSocket(SSLSocket sslSocket) throws IOException
        {
            Class<? extends SSLSocket> socketClass = sslSocket.getClass();
            try
            {
                Method supportedKeyParamsMethod = socketClass.getMethod("setSupportedTokenBindingKeyParams", byte[].class);
                Object supported = new byte[]{2}; //
                supportedKeyParamsMethod.invoke(sslSocket, supported);
            }
            catch (InvocationTargetException | IllegalAccessException e)
            {
                throw new IOException("Exception thrown by an invoked method on SSLSocket.", e);
            }
            catch (NoSuchMethodException e)
            {
                throw new IOException("No!!!!", e);
            }

            sslSocket.setEnabledProtocols(new String[]{"TLSv1.2"});
            sslSocket.addHandshakeCompletedListener(new MyHandshakeCompletedListener());
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

                System.out.println("EKM " + Arrays.toString(ekm));
                
                try
                {
                    TokenBindingMessageMaker maker = new TokenBindingMessageMaker().ekm(ekm).providedTokenBinding(TokenBindingKeyParameters.ECDSAP256, keyPair);
                    String tbmsg = maker.makeEncodedTokenBindingMessage();
                    HttpClientTest.tokenBindingHeader = tbmsg;    // hacky
                }
                catch (GeneralSecurityException e)
                {
                    e.printStackTrace();
                }

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

    static class OverlyTrustingTrustStrategy implements TrustStrategy
    {
        @Override
        public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException
        {
            return true;
        }
    }
}
