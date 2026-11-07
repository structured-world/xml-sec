import java.nio.file.*;

/**
 * A XAdES-BASELINE-B signature made by DSS, the start of the lifecycle that
 * xml-sec continues. Arguments: PKCS#12 key store (alias "signer", password
 * "dss"), packaging (ENVELOPED, ENVELOPING, DETACHED or INTERNALLY_DETACHED),
 * the data to sign, the signing time in Unix seconds and the output file.
 */
public class SignProbe {
    public static void main(String[] args) throws Exception {
        var signer = Lifecycle.Signer.load(Path.of(args[0]));
        var data = Lifecycle.named(Path.of(args[2]));
        Lifecycle.sign(signer, args[1], data, Long.parseLong(args[3])).save(args[4]);
    }
}
