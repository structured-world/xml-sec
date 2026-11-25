import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Date;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
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
 * reports. An input, its anchors or a policy that cannot be read is such a
 * failure, written for that case alone; the input and the policy
 * are read before DSS selects a validator, so only an input DSS has in hand
 * can be refused, and DSS's wrapping of a policy read error never reads as
 * a refusal.
 */
public class CorpusProbe {
    public static void main(String[] args) throws Exception {
        for (var line : Files.readAllLines(Path.of(args[0]))) {
            if (line.isBlank()) {
                continue;
            }
            var fields = line.split("\t", -1);
            var anchors = new ArrayList<byte[]>();
            // Anchors that cannot be read fail this case under every policy,
            // as an unreadable input does; the later cases still run.
            String unreadAnchors = null;
            try (var files = Files.list(Path.of(fields[3]))) {
                for (var file : files.sorted().toList()) {
                    anchors.add(Files.readAllBytes(file));
                }
            } catch (Exception error) {
                var trace = new StringWriter();
                error.printStackTrace(new PrintWriter(trace));
                unreadAnchors = trace.toString();
            }
            for (int pair = 4; pair + 1 < fields.length; pair += 2) {
                if (unreadAnchors != null) {
                    var output = Path.of(fields[pair + 1]);
                    Files.createDirectories(output);
                    Files.writeString(output.resolve("error.txt"), unreadAnchors);
                    continue;
                }
                var output = Path.of(fields[pair + 1]);
                Files.createDirectories(output);
                InMemoryDocument input;
                byte[] policy;
                try {
                    input = new InMemoryDocument(Files.readAllBytes(Path.of(fields[1])), Path.of(fields[1]).getFileName().toString());
                    policy = Files.readAllBytes(Path.of(fields[pair]));
                } catch (Exception error) {
                    var trace = new StringWriter();
                    error.printStackTrace(new PrintWriter(trace));
                    Files.writeString(output.resolve("error.txt"), trace.toString());
                    continue;
                }
                SignedDocumentValidator validator;
                try {
                    validator = SignedDocumentValidator.fromDocument(input);
                } catch (Exception refusal) {
                    Files.writeString(output.resolve("refused.txt"), String.valueOf(refusal.getMessage()));
                    continue;
                }
                try {
                    validator.setCertificateVerifier(Lifecycle.verifier(anchors, null));
                    validator.setValidationTime(Date.from(java.time.Instant.ofEpochSecond(Long.parseLong(fields[2]))));
                    validator.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
                    Reports reports;
                    try {
                        reports = validator.validateDocument(new ByteArrayInputStream(policy));
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
