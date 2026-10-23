import java.nio.file.*;
import java.time.Instant;
import java.util.Date;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/** Independent local profile reports. No implicit certificate/revocation fetching. */
public class Probe {
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
        validator.setValidationTime(Date.from(Instant.ofEpochSecond(1800000000)));
        validator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
        var reports = validator.validateDocument();
        Path output = Path.of(args[2]);
        Files.createDirectories(output);
        Files.writeString(output.resolve("diagnostic.xml"), reports.getXmlDiagnosticData());
        Files.writeString(output.resolve("detailed.xml"), reports.getXmlDetailedReport());
        Files.writeString(output.resolve("simple.xml"), reports.getXmlSimpleReport());
    }
}
