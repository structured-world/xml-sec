import java.nio.file.*;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

/**
 * Independent long-term validation of one signature. Only the supplied anchor
 * is trusted, nothing is fetched: every status comes from the document itself.
 * Arguments: document, anchor DER, validation time in Unix seconds, output,
 * and the detached content its reference names, if any.
 */
public class LevelProbe {
    public static void main(String[] args) throws Exception {
        DSSDocument detached = args.length > 4 ? Lifecycle.named(Path.of(args[4])) : null;
        var reports = Lifecycle.validate(
            new FileDocument(args[0]),
            Lifecycle.verifier(Files.readAllBytes(Path.of(args[1])), null),
            Long.parseLong(args[2]),
            ValidationLevel.ARCHIVAL_DATA,
            detached);
        Path output = Path.of(args[3]);
        Files.createDirectories(output);
        Files.writeString(output.resolve("diagnostic.xml"), reports.getXmlDiagnosticData());
        Files.writeString(output.resolve("detailed.xml"), reports.getXmlDetailedReport());
        Files.writeString(output.resolve("simple.xml"), reports.getXmlSimpleReport());
        System.out.print(Lifecycle.lines(reports));
    }
}
