import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.*;
import java.util.ArrayList;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.FileDocument;

/**
 * DSS reports over a whole corpus in one JVM. Each line of the manifest is
 * tab-separated: a case name, the input file, the validation time as Unix
 * seconds, a directory of DER trust anchors and the output directory. Every
 * case is validated at the archival level with DSS's default policy, the
 * document's own material and those anchors only; nothing is fetched. A case
 * DSS cannot validate leaves its exception in error.txt instead of reports.
 */
public class CorpusProbe {
    public static void main(String[] args) throws Exception {
        for (var line : Files.readAllLines(Path.of(args[0]))) {
            if (line.isBlank()) {
                continue;
            }
            var fields = line.split("\t", -1);
            var output = Path.of(fields[4]);
            Files.createDirectories(output);
            try {
                var anchors = new ArrayList<byte[]>();
                try (var files = Files.list(Path.of(fields[3]))) {
                    for (var file : files.sorted().toList()) {
                        anchors.add(Files.readAllBytes(file));
                    }
                }
                var reports = Lifecycle.validate(
                    new FileDocument(fields[1]),
                    Lifecycle.verifier(anchors, null),
                    Long.parseLong(fields[2]),
                    ValidationLevel.ARCHIVAL_DATA,
                    null);
                Files.writeString(output.resolve("diagnostic.xml"), reports.getXmlDiagnosticData());
                Files.writeString(output.resolve("detailed.xml"), reports.getXmlDetailedReport());
                Files.writeString(output.resolve("simple.xml"), reports.getXmlSimpleReport());
            } catch (Exception error) {
                var trace = new StringWriter();
                error.printStackTrace(new PrintWriter(trace));
                Files.writeString(output.resolve("error.txt"), trace.toString());
            }
            System.out.println(fields[0]);
        }
    }
}
