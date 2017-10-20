package temp.random;

import b_c.unbearable.client.TokenBindingMessageMaker;
import b_c.unbearable.messages.TokenBindingKeyParameters;
import b_c.unbearable.utils.EcKeyUtil;
import b_c.unbearable.utils.RsaKeyUtil;
import b_c.unbearable.jsseboot.UnbearableJsseAdapter;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 *
 */
public class HttpClientAgainTest
{
    public static final String TB_HEADER_CTX_NAME = "tb-header";
    static KeyPair ecKeyPair;
    static KeyPair rsaKeyPair;

    static {
        try {
            rsaKeyPair = RsaKeyUtil.generate2048RsaKeyPair();
            ecKeyPair = EcKeyUtil.generateEcP256KeyPair();
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
                .register("https", sslsf)
                .build();

        BasicHttpClientConnectionManager connManager = new BasicHttpClientConnectionManager(r);
        CloseableHttpClient httpclient = HttpClients.custom()
                .setConnectionManager(connManager)
                .setRequestExecutor(new TokenBindingHttpRequestExecutor())
                .build();

        HttpClientContext context = HttpClientContext.create();


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

    @Test
    public void mehSleep() throws Exception {

        SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(new OverlyTrustingTrustStrategy()).build();

        LayeredConnectionSocketFactory sslsf = new TokenBindingSSLConnectionSocketFactory(sslContext);
        Registry<ConnectionSocketFactory> r = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("https", sslsf)
                .build();

        BasicHttpClientConnectionManager connManager = new BasicHttpClientConnectionManager(r);
        CloseableHttpClient httpclient = HttpClients.custom()
                .setConnectionManager(connManager)
                .setRequestExecutor(new TokenBindingHttpRequestExecutor())
                .build();

        HttpClientContext context = HttpClientContext.create();

        int sleepy = 33000;

        for (int i = 0; i < 10; i++)
        {
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

            System.out.println(i + " bout to sleep for " + sleepy);
            Thread.sleep(sleepy);
           // sleepy = sleepy * 2;
        }

    }


    static class TokenBindingHttpRequestExecutor extends HttpRequestExecutor {
        @Override
        public HttpResponse execute(HttpRequest request, HttpClientConnection conn, HttpContext context) throws IOException, HttpException
        {
            String tbh = (String) context.getAttribute(TB_HEADER_CTX_NAME);
            System.out.println("ctx my-id in top execute: " + tbh);

            if (tbh == null)
            {
                ManagedHttpClientConnection managedHttpClientConnection = (ManagedHttpClientConnection) conn;
                Socket socket = managedHttpClientConnection.getSocket();
                needName(context, (SSLSocket) socket);
            }

            System.out.println("ctx my-id in end execute: " + context.getAttribute(TB_HEADER_CTX_NAME));
            String value = (String) context.getAttribute(TB_HEADER_CTX_NAME);
            if (value != null) {
                request.setHeader("Sec-Token-Binding", value);
            }
            return super.execute(request, conn, context);
        }
    }

    static void needName(HttpContext context, SSLSocket sslSocket) {
        UnbearableJsseAdapter unbearableJsseAdapter = new UnbearableJsseAdapter();
        try
        {
            UnbearableJsseAdapter.TlsTbInfo tbTlsInfo = unbearableJsseAdapter.getTbInfo(sslSocket);
            byte[] ekm = tbTlsInfo.getEkm();
            try
            {
                Byte negotiatedKeyParamsId = tbTlsInfo.getNegotiatedKeyParamsId();
                if (negotiatedKeyParamsId != null) {
                    KeyPair kp = null;
                    switch (negotiatedKeyParamsId)
                    {
                        case TokenBindingKeyParameters.ECDSAP256:
                            kp = ecKeyPair;
                            break;
                        case TokenBindingKeyParameters.RSA2048_PKCS1_5:
                        case TokenBindingKeyParameters.RSA2048_PSS:
                            kp = rsaKeyPair;
                            break;
                    }
                    TokenBindingMessageMaker maker = new TokenBindingMessageMaker().ekm(ekm).providedTokenBinding(negotiatedKeyParamsId, kp);
                    String tbmsg = maker.makeEncodedTokenBindingMessage();
                    context.setAttribute(TB_HEADER_CTX_NAME, tbmsg);
                }

            }
            catch (GeneralSecurityException e)
            {
                throw new RuntimeException("TEMP ", e);
            }
        }
        catch (NoSuchMethodException e)
        {
            throw new RuntimeException("Problem calling into custom JSSE socket", e);
        }
    }

    static class TokenBindingSSLConnectionSocketFactory extends SSLConnectionSocketFactory {

        public TokenBindingSSLConnectionSocketFactory(SSLContext sslContext) {
            super(sslContext);
        }

        @Override
        public Socket connectSocket(int connectTimeout, Socket socket, HttpHost host, InetSocketAddress remoteAddress, InetSocketAddress localAddress, HttpContext context) throws IOException
        {
            System.out.println("calling super connectSocket " + socket);
            Socket connectedSocket = super.connectSocket(connectTimeout, socket, host, remoteAddress, localAddress, context);
            System.out.println("returned from super connectSocket " + connectedSocket);
            System.out.println("ctx my-id in connect sock before: " + context.getAttribute(TB_HEADER_CTX_NAME));

            needName(context, (SSLSocket) connectedSocket);
            
            System.out.println("ctx my-id in connect sock after: " + context.getAttribute(TB_HEADER_CTX_NAME));

            return connectedSocket;
        }

        @Override
        protected void prepareSocket(SSLSocket sslSocket) throws IOException
        {

            try
            {
                UnbearableJsseAdapter unbearableJsseAdapter = new UnbearableJsseAdapter();
                unbearableJsseAdapter.setSupportedTokenBindingKeyParams(sslSocket, new byte[] {2, 1});
            }
            catch (NoSuchMethodException e)
            {
                throw new IOException("Problem calling into custom JSSE socket", e);
            }

            sslSocket.setEnabledProtocols(new String[]{"TLSv1.2"});
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
