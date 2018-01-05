/*

The MIT License (MIT)

Copyright (c) 2015 Alex Travelling With Code

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

NioSslClient.java, NioSslPeer.java, and NioSslServer.java were copied and
modified from the MIT Licensed https://github.com/alkarn/sslengine.example

 */
package alkarn.github.io.sslengine.example.example;

import testing.support.stuff.Helper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

/**
 * An SSL/TLS client that connects to a server using its IP address and port.
 * <p/>
 * After initialization of a {@link NioSslClient} object, {@link NioSslClient#connect()} should be called,
 * in order to establish connection with the server.
 * <p/>
 * When the connection between the client and the object is established, {@link NioSslClient} provides
 * a public write and read method, in order to communicate with its peer. 
 *
 * @author <a href="mailto:alex.a.karnezis@gmail.com">Alex Karnezis</a>
 */
public class NioSslClient extends NioSslPeer {
	
    /**
     * The remote address of the server this client is configured to connect to.
     */
	private String remoteAddress;

	/**
	 * The port of the server this client is configured to connect to.
	 */
	private int port;

	/**
	 * The engine that will be used to encrypt/decrypt data between this client and the server.
	 */
    private SSLEngine engine;

    /**
     * The socket channel that will be used as the transport link between this client and the server.
     */
    private SocketChannel socketChannel;


    /**
     * Initiates the engine to run as a client using peer information, and allocates space for the
     * buffers that will be used by the engine.
     *
     * @param protocol The SSL/TLS protocol to be used. Java 1.6 will only run with up to TLSv1 protocol. Java 1.7 or higher also supports TLSv1.1 and TLSv1.2 protocols.
     * @param remoteAddress The IP address of the peer.
     * @param port The peer's port that will be used.
     * @throws Exception
     */
    public NioSslClient(String protocol, String remoteAddress, int port, byte[] supportedTokenBindingKeyParams) throws Exception  {
    	this.remoteAddress = remoteAddress;
    	this.port = port;

        SSLContext context = SSLContext.getInstance(protocol);
        TrustManager[] trustManagers = Helper.loadTrustManagers("password", "ts.jks");
        context.init(null, trustManagers, null);
        engine = context.createSSLEngine(remoteAddress, port);
        engine.setUseClientMode(true);

        if (supportedTokenBindingKeyParams != null) {
            Helper.setSupportedTokenBindingKeyParams(engine, supportedTokenBindingKeyParams);
        }

        SSLSession session = engine.getSession();
        myAppData = ByteBuffer.allocate(1024);
        myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(1024);
        peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
    }

    /**
     * Opens a socket channel to communicate with the configured server and tries to complete the handshake protocol.
     *
     * @return True if client established a connection with the server, false otherwise.
     * @throws Exception
     */
    public boolean connect() throws Exception {
    	socketChannel = SocketChannel.open();
    	socketChannel.configureBlocking(false);
    	socketChannel.connect(new InetSocketAddress(remoteAddress, port));
    	while (!socketChannel.finishConnect()) {
    		// can do something here...
    	}

    	engine.beginHandshake();
    	return doHandshake(socketChannel, engine);
    }

    /**
     * Public method to send a message to the server.
     *
     * @param message - message to be sent to the server.
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    public void write(String message) throws IOException {
        write(socketChannel, engine, message);
    }

    /**
     * Implements the write method that sends a message to the server the client is connected to,
     * but should not be called by the user, since socket channel and engine are inner class' variables.
     * {@link NioSslClient#write(String)} should be called instead.
     *
     * @param message - message to be sent to the server.
     * @param engine - the engine used for encryption/decryption of the data exchanged between the two peers.
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    @Override
    protected void write(SocketChannel socketChannel, SSLEngine engine, String message) throws IOException {

        myAppData.clear();
        myAppData.put(message.getBytes());
        myAppData.flip();
        while (myAppData.hasRemaining()) {
            // The loop has a meaning for (outgoing) messages larger than 16KB.
            // Every wrap call will remove 16KB from the original message and send it to the remote peer.
            myNetData.clear();
            SSLEngineResult result = engine.wrap(myAppData, myNetData);
            switch (result.getStatus()) {
            case OK:
                myNetData.flip();
                while (myNetData.hasRemaining()) {
                    socketChannel.write(myNetData);
                }
                break;
            case BUFFER_OVERFLOW:
                myNetData = enlargePacketBuffer(engine, myNetData);
                break;
            case BUFFER_UNDERFLOW:
                throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
            case CLOSED:
                closeConnection(socketChannel, engine);
                return;
            default:
                throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
            }
        }

    }

    /**
     * Public method to try to read from the server.
     *
     * @throws Exception
     */
    public String read() throws Exception {
        return read(socketChannel, engine);
    }

    /**
     * Will wait for response from the remote peer, until it actually gets something.
     * Uses {@link SocketChannel#read(ByteBuffer)}, which is non-blocking, and if
     * it gets nothing from the peer, waits for {@code waitToReadMillis} and tries again.
     * <p/>
     * Just like {@link NioSslClient#read(SocketChannel, SSLEngine)} it uses inner class' socket channel
     * and engine and should not be used by the client. {@link NioSslClient#read()} should be called instead.
     * 
     * @param socketChannel - 
     * @param engine - the engine used for encryption/decryption of the data exchanged between the two peers.
     * @throws Exception
     */
    @Override
    protected String read(SocketChannel socketChannel, SSLEngine engine) throws Exception  {

        String message = null;
        peerNetData.clear();
        int waitToReadMillis = 50;
        boolean exitReadLoop = false;
        while (!exitReadLoop) {
            int bytesRead = socketChannel.read(peerNetData);
            if (bytesRead > 0) {
                peerNetData.flip();
                while (peerNetData.hasRemaining()) {
                    peerAppData.clear();
                    SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
                    switch (result.getStatus()) {
                    case OK:
                        peerAppData.flip();
                        byte[] messageBytes = new byte[result.bytesProduced()];
                        peerAppData.get(messageBytes);
                        message = new String(messageBytes);
                        exitReadLoop = true;
                        break;
                    case BUFFER_OVERFLOW:
                        peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                        break;
                    case BUFFER_UNDERFLOW:
                        peerNetData = handleBufferUnderflow(engine, peerNetData);
                        break;
                    case CLOSED:
                        closeConnection(socketChannel, engine);
                        return null;
                    default:
                        throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                    }
                }
            } else if (bytesRead < 0) {
                handleEndOfStream(socketChannel, engine);
                return null;
            }
            Thread.sleep(waitToReadMillis);
        }
        return message;
    }

    /**
     * Should be called when the client wants to explicitly close the connection to the server.
     *
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    public void shutdown() throws IOException {
        closeConnection(socketChannel, engine);
        executor.shutdown();
    }

    public SSLEngine getEngine() {
        return engine;
    }
}
