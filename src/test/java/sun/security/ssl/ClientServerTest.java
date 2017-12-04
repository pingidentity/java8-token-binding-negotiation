package sun.security.ssl;

import alkarn.github.io.sslengine.example.example.NioSslClient;
import alkarn.github.io.sslengine.example.example.NioSslServer;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;
import testing.support.stuff.Helper;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;

/**
 * Some sanity tests of TLS handshaking using both SSLSocket and SSLSession with and without Token Binding being negotiated
 */
public class ClientServerTest {

    private final int PORT = 48443;

    private String[] messages = new String[] {
            "I want a hamburger. No, a cheeseburger. I want a hotdog. I want a milkshake.",
            "Oh, this is the worst-looking hat I ever saw. What, when you buy a hat like this I bet you get a free bowl of soup, huh?",
            "Remember Danny - Two wrongs don't make a right but three rights make a left.",
            "Oh, Danny, this isn't Russia. Is this Russia? This isn't Russia, is it? I didn't think so.",
            "Well, the world needs ditch diggers, too."
    };
    
    @Test
    public void engineToEngineNoTbAtAll() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, null);

        try {
            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runEngineClient(PORT, null, null);

        } finally {
            server.stop();
        }
    }

    @Test
    public void engineToEngineNoServerTb() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, null);

        try {
            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runEngineClient(PORT, new byte[] {TokenBindingExtension.ECDSAP256}, null);

        } finally {
            server.stop();
        }
    }

    @Test
    public void engineToEngineTbEc() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256, TokenBindingExtension.RSA2048_PKCS1_5} );

        try {
            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runEngineClient(PORT,  new byte[] {TokenBindingExtension.ECDSAP256}, TokenBindingExtension.ECDSAP256);

        } finally {
            server.stop();
        }
    }

    @Test
    public void engineToEngineNoTbFromClient() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256, TokenBindingExtension.RSA2048_PKCS1_5} );

        try {
            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runEngineClient(PORT,  null, null);

        } finally {
            server.stop();
        }
    }

    @Test
    public void socketToEngineNoTbAtAll() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, null);

        try {
            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runSocketClient(PORT, null, null);

        } finally {
            server.stop();
        }
    }

    @Test
    public void socketToEngineNoServerTb() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, null);

        try {
            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runSocketClient(PORT, new byte[] {TokenBindingExtension.ECDSAP256}, null);

        } finally {
            server.stop();
        }
    }

    @Test
    public void socketToEngineTbEc() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256, TokenBindingExtension.RSA2048_PKCS1_5});

        try {
            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runSocketClient(PORT, new byte[] {TokenBindingExtension.ECDSAP256}, TokenBindingExtension.ECDSAP256);

        } finally {
            server.stop();
        }
    }

    @Test
    public void socketToEngineTbRsa() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256, TokenBindingExtension.RSA2048_PKCS1_5});

        try {
            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runSocketClient(PORT, new byte[] {TokenBindingExtension.RSA2048_PKCS1_5}, TokenBindingExtension.RSA2048_PKCS1_5);

        } finally {
            server.stop();
        }
    }

    @Test
    public void engineToSocketNegoTbEc() throws Exception {

        Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256}));
        thread.start();
        waitForServerStartup();
        runEngineClient(PORT, new byte[] {TokenBindingExtension.ECDSAP256}, TokenBindingExtension.ECDSAP256);
    }

    @Test
    public void engineToSocketNegoTbRsa() throws Exception {

        Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256, TokenBindingExtension.RSA2048_PKCS1_5}));
        thread.start();
        waitForServerStartup();
        runEngineClient(PORT, new byte[] {TokenBindingExtension.RSA2048_PKCS1_5}, TokenBindingExtension.RSA2048_PKCS1_5);
    }

    @Test
    public void engineToSocketNoTbFromClient() throws Exception {

        Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256, TokenBindingExtension.RSA2048_PKCS1_5}));
        thread.start();
        waitForServerStartup();
        runEngineClient(PORT, null, null);
    }

    @Test
    public void engineToSocketNoTbAtAll() throws Exception {

        Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, null));
        thread.start();
        waitForServerStartup();
        runEngineClient(PORT, null, null);
    }
    
    @Test
    public void socketToSocketNegoTbEc() throws Exception {

        Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256}));
        thread.start();
        waitForServerStartup();
        runSocketClient(PORT, new byte[] {TokenBindingExtension.ECDSAP256}, TokenBindingExtension.ECDSAP256);
    }

    @Test
    public void socketToSocketNegoTbRsa() throws Exception {

        Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256, TokenBindingExtension.RSA2048_PSS}));
        thread.start();
        waitForServerStartup();
        runSocketClient(PORT, new byte[] {TokenBindingExtension.RSA2048_PSS, TokenBindingExtension.RSA2048_PSS}, TokenBindingExtension.RSA2048_PSS);
    }

    @Test
    public void socketToSocketNoTbFromClient() throws Exception {

        Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256, TokenBindingExtension.RSA2048_PKCS1_5}));
        thread.start();
        waitForServerStartup();
        runSocketClient(PORT, null, null);
    }

    @Test
    public void socketToSocketNoTbAtAll() throws Exception {

        Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, null));
        thread.start();
        waitForServerStartup();
        runSocketClient(PORT, null, null);
    }

    @Test
    public void socketToSocketServerNoTb() throws Exception {

        Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, null));
        thread.start();
        waitForServerStartup();
        runSocketClient(PORT, new byte[] {TokenBindingExtension.RSA2048_PKCS1_5, TokenBindingExtension.ECDSAP256}, null);
    }

    @Test
    public void socketToSocketNegoTbEcWithServerDefault() throws Exception {

        try {
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_SERVER_DEFAULT_SUPPORTED, "2,0");
            TokenBindingExtension.setUpDefaultSupportedKeyParams();
            
            Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, null));
            thread.start();
            waitForServerStartup();
            runSocketClient(PORT, new byte[] {TokenBindingExtension.ECDSAP256}, TokenBindingExtension.ECDSAP256);

        } finally {
            resetDefaultSupportedKeyParams();
        }
    }

    @Test
    public void socketToSocketNegoTbEcWithServerAndClientDefault() throws Exception {

        try {
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_SERVER_DEFAULT_SUPPORTED, "2,0");
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_CLEINT_DEFAULT_SUPPORTED, "2");
            TokenBindingExtension.setUpDefaultSupportedKeyParams();

            Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, null));
            thread.start();
            waitForServerStartup();
            runSocketClient(PORT, null, TokenBindingExtension.ECDSAP256);

        } finally {
            resetDefaultSupportedKeyParams();
        }
    }

    @Test
    public void socketToSocketNegoTbEcWithClientDefault() throws Exception {

        try {
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_CLEINT_DEFAULT_SUPPORTED, "2");
            TokenBindingExtension.setUpDefaultSupportedKeyParams();

            Thread thread = new Thread(new SimpleSocketEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.RSA2048_PSS,TokenBindingExtension.ECDSAP256}));
            thread.start();
            waitForServerStartup();
            runSocketClient(PORT, null, TokenBindingExtension.ECDSAP256);

        } finally {
            resetDefaultSupportedKeyParams();
        }
    }

    @Test
    public void socketToEngineTbEcWithServerDefault() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, null);

        try {
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_SERVER_DEFAULT_SUPPORTED, "2,0");
            TokenBindingExtension.setUpDefaultSupportedKeyParams();

            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runSocketClient(PORT, new byte[] {TokenBindingExtension.ECDSAP256}, TokenBindingExtension.ECDSAP256);

        } finally {
            server.stop();
            resetDefaultSupportedKeyParams();
        }
    }

    @Test
    public void socketToEngineTbRsaWithClientDefault() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.ECDSAP256, TokenBindingExtension.RSA2048_PKCS1_5});

        try {
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_CLEINT_DEFAULT_SUPPORTED, "0,1");
            TokenBindingExtension.setUpDefaultSupportedKeyParams();

            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runSocketClient(PORT, null, TokenBindingExtension.RSA2048_PKCS1_5);

        } finally {
            server.stop();
            resetDefaultSupportedKeyParams();
        }
    }

    @Test
    public void socketToEngineTbOverrideDefaults() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, new byte[] {TokenBindingExtension.RSA2048_PKCS1_5});

        try {
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_CLEINT_DEFAULT_SUPPORTED, "2");
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_CLEINT_DEFAULT_SUPPORTED, "2");

            TokenBindingExtension.setUpDefaultSupportedKeyParams();

            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runSocketClient(PORT, new byte[] {TokenBindingExtension.RSA2048_PKCS1_5}, TokenBindingExtension.RSA2048_PKCS1_5);

        } finally {
            server.stop();
            resetDefaultSupportedKeyParams();
        }
    }


    @Test
    public void engineToEngineTbEcWithServerDefault() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, null );

        try {
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_SERVER_DEFAULT_SUPPORTED, "2,1");
            TokenBindingExtension.setUpDefaultSupportedKeyParams();

            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runEngineClient(PORT,  new byte[] {TokenBindingExtension.ECDSAP256}, TokenBindingExtension.ECDSAP256);

        } finally {
            server.stop();
            resetDefaultSupportedKeyParams();
        }
    }

    @Test
    public void engineToEngineTbEcWithServerAndClientDefault() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, null );

        try {
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_SERVER_DEFAULT_SUPPORTED, "2,1");
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_CLEINT_DEFAULT_SUPPORTED, "2,1");

            TokenBindingExtension.setUpDefaultSupportedKeyParams();

            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runEngineClient(PORT,  null, TokenBindingExtension.ECDSAP256);

        } finally {
            server.stop();
            resetDefaultSupportedKeyParams();
        }
    }

    @Test
    public void engineToEngineTbEcWithClientDefault() throws Exception {

        SimpleishEngineEchoServerRunnable server = new SimpleishEngineEchoServerRunnable(PORT, new byte[] {2,0} );

        try {
            System.setProperty(TokenBindingExtension.PROPERTY_NAME_CLEINT_DEFAULT_SUPPORTED, "2,1");

            TokenBindingExtension.setUpDefaultSupportedKeyParams();

            Thread thread = new Thread(server);
            thread.start();
            waitForServerStartup();

            runEngineClient(PORT,  null, TokenBindingExtension.ECDSAP256);

        } finally {
            server.stop();
            resetDefaultSupportedKeyParams();
        }
    }

    void runEngineClient(int port, byte[] supportedTokenBindingKeyParams, Byte expectedNegotiatedKeyParams) throws Exception {

        NioSslClient client = new NioSslClient("TLSv1.2", "localhost", port, supportedTokenBindingKeyParams);
        try {
            client.connect();

            SSLEngine engine = client.getEngine();

            Byte negotiatedTokenBindingKeyParams = Helper.getNegotiatedTokenBindingKeyParams(engine);
            Assert.assertThat(negotiatedTokenBindingKeyParams, CoreMatchers.equalTo(expectedNegotiatedKeyParams));

            for (String message : messages) {
                message = message + "\n";
                client.write(message);
                String read = client.read();
                Assert.assertThat(read, CoreMatchers.equalTo(message));
            }

            client.write(Helper.SEND_EKM + "\n");
            String encodedEkmFromServer = client.read();
            encodedEkmFromServer = encodedEkmFromServer.substring(0, encodedEkmFromServer.length() - 1);
            String encodedEKM = Helper.getEncodedTokenBindingEKM(engine);
            Assert.assertThat(encodedEkmFromServer, CoreMatchers.equalTo(encodedEKM));

        } finally {
            client.shutdown();
        }
    }

    void runSocketClient(int port, byte[] supportedTokenBindingKeyParams, Byte expectedNegotiatedKeyParams) throws Exception {

        TrustManager[] trustManagers = Helper.loadTrustManagers("password", "ts.jks");
        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(null, trustManagers, null);

        SSLSocketFactory socketFactory = sslCtx.getSocketFactory();

        try (SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", port))
        {
            Helper.setSupportedTokenBindingKeyParams(socket, supportedTokenBindingKeyParams);

            SSLSession session = socket.getSession();
            Assert.assertNotNull(session);

            Byte negotiatedTokenBindingKeyParams = Helper.getNegotiatedTokenBindingKeyParams(socket);
            Assert.assertThat(negotiatedTokenBindingKeyParams, CoreMatchers.equalTo(expectedNegotiatedKeyParams));

            PrintWriter writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            for (String message : messages) {
                writer.println(message);
                writer.flush();
                Assert.assertThat(reader.readLine(), CoreMatchers.equalTo(message));
            }

            writer.println(Helper.SEND_EKM);
            writer.flush();
            String encodedEkmFromServer = reader.readLine();
            String encodedEKM = Helper.getEncodedTokenBindingEKM(socket);
            Assert.assertThat(encodedEkmFromServer, CoreMatchers.equalTo(encodedEKM));

            writer.close();
            reader.close();
        }
    }

    class SimpleishEngineEchoServerRunnable implements Runnable {

        NioSslServer server;

        public SimpleishEngineEchoServerRunnable(int port, byte[] supportedTokenBindingKeyParams) throws Exception {
            server = new NioSslServer("TLSv1.2", "localhost", port, supportedTokenBindingKeyParams);
        }

        @Override
        public void run() {
            try {
                server.start();
            } catch (Exception e) {
                e.printStackTrace();
                Assert.fail(e.getMessage());
            }
        }

        void stop() throws Exception{
            server.stop();
        }
    }

    class SimpleSocketEchoServerRunnable implements Runnable {

        int port;
        byte[] supportedTokenBindingKeyParams;

        SimpleSocketEchoServerRunnable(int port, byte[] supportedTokenBindingKeyParams)
        {
            this.port = port;
            this.supportedTokenBindingKeyParams = supportedTokenBindingKeyParams;
        }

        @Override
        public void run() {
            try {

                SSLContext sslCtx = SSLContext.getInstance("TLS");
                KeyManager[] keyManagers = Helper.loadKeyManager("password", "ks.jks");
                sslCtx.init(keyManagers, null, null);

                ServerSocketFactory ssocketFactory = sslCtx.getServerSocketFactory();
                ServerSocket ssocket = ssocketFactory.createServerSocket(port);

                SSLSocket socket = (SSLSocket) ssocket.accept();

                if (supportedTokenBindingKeyParams != null) {
                    Helper.setSupportedTokenBindingKeyParams(socket, supportedTokenBindingKeyParams);
                }

                PrintWriter writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String line;
                while ((line=reader.readLine())!= null) {

                    if (line.equals(Helper.SEND_EKM)) {
                        String encodedEKM = Helper.getEncodedTokenBindingEKM(socket);
                         writer.println(encodedEKM);
                    }  else {
                        writer.println(line);
                    }

                    writer.flush();
                }

                writer.close();
                reader.close();
                socket.close();
                ssocket.close();
            } catch (Exception e) {
                e.printStackTrace();
                Assert.fail(e.getMessage());
            }
        }
    }
    
    private void waitForServerStartup() throws InterruptedException {
        Thread.sleep(1000);   // Give the server a little time to start.
    }

    private void resetDefaultSupportedKeyParams()
    {
        System.clearProperty(TokenBindingExtension.PROPERTY_NAME_SERVER_DEFAULT_SUPPORTED);
        System.clearProperty(TokenBindingExtension.PROPERTY_NAME_CLEINT_DEFAULT_SUPPORTED);
        TokenBindingExtension.setUpDefaultSupportedKeyParams();
    }

}
