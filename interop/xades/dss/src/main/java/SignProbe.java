import java.nio.file.*;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

/**
 * A XAdES-BASELINE-B signature made by DSS, the start of the lifecycle that
 * xml-sec continues. Arguments: PKCS#12 key store (alias "signer", password
 * "dss"), packaging (ENVELOPED, ENVELOPING, DETACHED or INTERNALLY_DETACHED),
 * the data to sign, the signing time in Unix seconds, the output file and
 * DSS's name of the signature algorithm (RSA_SHA256, ED448, ...).
 */
public class SignProbe {
    public static void main(String[] args) throws Exception {
        var signer = Lifecycle.Signer.load(Path.of(args[0]));
        var data = Lifecycle.named(Path.of(args[2]));
        var algorithm = SignatureAlgorithm.valueOf(args[5]);
        Lifecycle.sign(Lifecycle.signing(), signer, args[1], data, Long.parseLong(args[3]), algorithm)
                .save(args[4]);
    }
}
