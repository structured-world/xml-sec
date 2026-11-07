import java.nio.file.*;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

/**
 * DSS augments a signature to a baseline level, nothing fetched: the TSA is a
 * local key entity and every status comes from the supplied files. Arguments:
 * input, output, level (T, LT or LTA; LTA on a B-LTA signature renews it),
 * trust anchor DER, TSA PKCS#12 (alias "tsa", password "dss"), the token time
 * in Unix seconds, a directory of DER evidence (*.cer, *.crl, *.ocsp), and the
 * detached content the signature's reference names, if any. A refusal prints
 * "refused" with DSS's reason and exits with status 3.
 */
public class AugmentProbe {
    public static void main(String[] args) throws Exception {
        var verifier = Lifecycle.verifier(Files.readAllBytes(Path.of(args[3])), Path.of(args[6]));
        var tsa = Lifecycle.tsa(Path.of(args[4]), Long.parseLong(args[5]));
        DSSDocument detached = args.length > 7 ? Lifecycle.named(Path.of(args[7])) : null;
        DSSDocument extended;
        try {
            extended = Lifecycle.extend(verifier, tsa, new FileDocument(args[0]), args[2], detached);
        } catch (RuntimeException refusal) {
            System.out.println("refused " + refusal.getMessage());
            System.exit(3);
            return;
        }
        extended.save(args[1]);
        System.out.println("augmented " + args[2]);
    }
}
