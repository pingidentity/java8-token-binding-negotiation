package sun.security.ssl;

import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;

/**
 *
 */
public class KeyingMaterialExporter
{
    static byte[] ekm(String label,
                      int length,
                      ProtocolVersion protocolVersion,
                      SSLSessionImpl sess,
                      byte[] clientRandom,
                      byte[] serverRandom)
            throws DigestException, NoSuchAlgorithmException
    {
        byte[] rawMaster = sess.getMasterSecret().getEncoded();
        byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
        byte[] seed = TlsPrf.concat(clientRandom, serverRandom);
        if (protocolVersion.v == 0x0303) {
            CipherSuite.PRF prfAlg = sess.getSuite().prfAlg;
            return TlsPrf.doTLS12PRF(rawMaster, labelBytes, seed, length,
                    prfAlg.getPRFHashAlg(), prfAlg.getPRFHashLength(), prfAlg.getPRFBlockSize());
        } else if (protocolVersion.v == 0x0302 || protocolVersion.v == 0x0301 ) {
            return TlsPrf.doTLS10PRF(rawMaster, labelBytes, seed, length);
        } else {
            throw new IllegalStateException("EKM not supported for version " + protocolVersion);
        }
    }
}
