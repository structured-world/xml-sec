import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Date;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * DSS reports over a whole corpus in one JVM. Each line of the manifest is
 * tab-separated: a case name, the input file, the validation time as Unix
 * seconds, a directory of DER trust anchors, then pairs of a validation
 * policy file and its output directory. Every case is validated at the
 * archival level under each policy, with the document's own material and
 * those anchors only; nothing is fetched. An input DSS refuses, as a signed
 * document it does not read or through its own DSSException while
 * validating it (an unsupported algorithm, say), leaves that refusal in
 * refused.txt; any other exception, which is a failure of the run rather
 * than an answer about the input, leaves its trace in error.txt instead of
 * reports.
 */
public class CorpusProbe {
    public static void main(String[] args) throws Exception {
        for (var line : Files.readAllLines(Path.of(args[0]))) {
            if (line.isBlank()) {
                continue;
            }
            var fields = line.split("\t", -1);
            var anchors = new ArrayList<byte[]>();
            try (var files = Files.list(Path.of(fields[3]))) {
                for (var file : files.sorted().toList()) {
                    anchors.add(Files.readAllBytes(file));
                }
            }
            for (int pair = 4; pair + 1 < fields.length; pair += 2) {
                var output = Path.of(fields[pair + 1]);
                Files.createDirectories(output);
                SignedDocumentValidator validator;
                try {
                    validator = SignedDocumentValidator.fromDocument(new FileDocument(fields[1]));
                } catch (Exception refusal) {
                    Files.writeString(output.resolve("refused.txt"), String.valueOf(refusal.getMessage()));
                    continue;
                }
                try {
                    validator.setCertificateVerifier(Lifecycle.verifier(anchors, null));
                    validator.setValidationTime(Date.from(java.time.Instant.ofEpochSecond(Long.parseLong(fields[2]))));
                    validator.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
                    Reports reports;
                    try (var policy = Files.newInputStream(Path.of(fields[pair]))) {
                        reports = validator.validateDocument(policy);
                    } catch (DSSException refusal) {
                        Files.writeString(output.resolve("refused.txt"), String.valueOf(refusal.getMessage()));
                        continue;
                    }
                    Files.writeString(output.resolve("diagnostic.xml"), reports.getXmlDiagnosticData());
                    Files.writeString(output.resolve("detailed.xml"), reports.getXmlDetailedReport());
                    Files.writeString(output.resolve("simple.xml"), reports.getXmlSimpleReport());
                } catch (Exception error) {
                    var trace = new StringWriter();
                    error.printStackTrace(new PrintWriter(trace));
                    Files.writeString(output.resolve("error.txt"), trace.toString());
                }
            }
            System.out.println(fields[0]);
        }
    }
}
