import java.nio.file.*;
import java.time.Instant;
import java.util.Date;
import java.util.Base64;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.enumerations.Level;

/** Separate profile-binding investigation; no change to the original probe. */
public class BindingProbe {
    public static void main(String[] args) throws Exception {
        if (args.length < 3 || args.length > 4) throw new IllegalArgumentException("fixture root-certificate output [structure-fail]");
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
        var policy = (EtsiValidationPolicy) ValidationPolicyLoader.fromDefaultValidationPolicy().create();
        if (args.length == 4) {
            if (!args[3].equals("structure-fail")) throw new IllegalArgumentException("unknown policy experiment");
            policy.getSignatureConstraints().getStructuralValidation().setLevel(Level.FAIL);
        }
        var reports = validator.validateDocument(policy);
        Path output = Path.of(args[2]);
        Files.createDirectories(output);
        Files.writeString(output.resolve("diagnostic.xml"), reports.getXmlDiagnosticData());
        Files.writeString(output.resolve("detailed.xml"), reports.getXmlDetailedReport());
        Files.writeString(output.resolve("simple.xml"), reports.getXmlSimpleReport());
        var signature = reports.getDiagnosticData().getSignatures().get(0);
        var selected = signature.getSigningCertificate();
        StringBuilder facts = new StringBuilder();
        facts.append("structural_policy=").append(policy.getSignatureConstraints().getStructuralValidation().getLevel()).append('\n');
        facts.append("selected_certificate=").append(selected == null ? "null" : selected.getId()).append('\n');
        facts.append("selected_certificate_reference_null=").append(signature.getSigningCertificateReference() == null).append('\n');
        int index = 0;
        for (var reference : signature.getSigningCertificateReferences()) {
            facts.append("reference.").append(index).append(".match=").append(reference.isDigestValueMatch()).append('\n');
            facts.append("reference.").append(index).append(".digest=")
                .append(Base64.getEncoder().encodeToString(reference.getDigestAlgoAndValue().getDigestValue())).append('\n');
            index++;
        }
        Files.writeString(output.resolve("binding-facts.txt"), facts.toString());
    }
}
