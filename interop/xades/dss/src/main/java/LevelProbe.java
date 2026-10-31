import java.nio.file.*;
import java.time.Instant;
import java.util.Date;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * Independent long-term validation of one signature. Only the supplied anchor
 * is trusted, nothing is fetched: every status comes from the document itself.
 * Arguments: document, anchor DER, validation time in Unix seconds, output,
 * and the detached content its reference names, if any.
 */
public class LevelProbe {
    public static void main(String[] args) throws Exception {
        var verifier = new CommonCertificateVerifier();
        verifier.setAIASource(null);
        verifier.setOcspSource(null);
        verifier.setCrlSource(null);
        var anchors = new CommonTrustedCertificateSource();
        anchors.addCertificate(DSSUtils.loadCertificate(Files.readAllBytes(Path.of(args[1]))));
        verifier.setTrustedCertSources(anchors);
        var validator = SignedDocumentValidator.fromDocument(new FileDocument(args[0]));
        validator.setCertificateVerifier(verifier);
        if (args.length > 4) {
            var content = new FileDocument(args[4]);
            content.setName(Path.of(args[4]).getFileName().toString());
            validator.setDetachedContents(java.util.List.of(content));
        }
        validator.setValidationTime(Date.from(Instant.ofEpochSecond(Long.parseLong(args[2]))));
        validator.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
        var reports = validator.validateDocument();
        Path output = Path.of(args[3]);
        Files.createDirectories(output);
        Files.writeString(output.resolve("diagnostic.xml"), reports.getXmlDiagnosticData());
        Files.writeString(output.resolve("detailed.xml"), reports.getXmlDetailedReport());
        Files.writeString(output.resolve("simple.xml"), reports.getXmlSimpleReport());
        var simple = reports.getSimpleReport();
        for (var id : simple.getSignatureIdList()) {
            System.out.printf(
                "%s format=%s indication=%s subindication=%s errors=%s%n",
                id,
                simple.getSignatureFormat(id),
                simple.getIndication(id),
                simple.getSubIndication(id),
                simple.getAdESValidationErrors(id).stream().map(message -> message.getValue()).toList());
        }
    }
}
