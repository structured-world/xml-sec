import java.nio.file.*;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.FileDocument;

/** Independent local profile reports. No implicit certificate/revocation fetching. */
public class Probe {
    public static void main(String[] args) throws Exception {
        var reports = Lifecycle.validate(
            new FileDocument(args[0]),
            Lifecycle.verifier(Files.readAllBytes(Path.of(args[1])), null),
            1800000000L,
            ValidationLevel.BASIC_SIGNATURES,
            null);
        Path output = Path.of(args[2]);
        Files.createDirectories(output);
        Files.writeString(output.resolve("diagnostic.xml"), reports.getXmlDiagnosticData());
        Files.writeString(output.resolve("detailed.xml"), reports.getXmlDetailedReport());
        Files.writeString(output.resolve("simple.xml"), reports.getXmlSimpleReport());
    }
}
