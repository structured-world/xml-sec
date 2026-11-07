import java.nio.file.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

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
        var verifier = new CommonCertificateVerifier();
        verifier.setAIASource(null);
        var anchors = new CommonTrustedCertificateSource();
        anchors.addCertificate(DSSUtils.loadCertificate(Files.readAllBytes(Path.of(args[3]))));
        verifier.setTrustedCertSources(anchors);
        var certificates = new CommonCertificateSource();
        List<DSSDocument> crls = new ArrayList<>();
        List<DSSDocument> responses = new ArrayList<>();
        try (var files = Files.list(Path.of(args[6]))) {
            for (var file : files.sorted().toList()) {
                var name = file.getFileName().toString();
                if (name.endsWith(".cer")) {
                    certificates.addCertificate(DSSUtils.loadCertificate(Files.readAllBytes(file)));
                } else if (name.endsWith(".crl")) {
                    crls.add(new FileDocument(file.toFile()));
                } else if (name.endsWith(".ocsp")) {
                    responses.add(new FileDocument(file.toFile()));
                }
            }
        }
        verifier.setAdjunctCertSources(certificates);
        verifier.setCrlSource(crls.isEmpty() ? null : new ExternalResourcesCRLSource(crls.toArray(DSSDocument[]::new)));
        verifier.setOcspSource(responses.isEmpty() ? null : new ExternalResourcesOCSPSource(responses.toArray(DSSDocument[]::new)));
        char[] password = "dss".toCharArray();
        var tsa = new KeyEntityTSPSource(Path.of(args[4]).toFile(), "PKCS12", password, "tsa", password);
        tsa.setTsaPolicy("1.3.6.1.4.1.13762.3");
        tsa.setProductionTime(Date.from(Instant.ofEpochSecond(Long.parseLong(args[5]))));
        var service = new XAdESService(verifier);
        service.setTspSource(tsa);
        var parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.valueOf("XAdES_BASELINE_" + args[2]));
        if (args.length > 7) {
            var content = new FileDocument(args[7]);
            content.setName(Path.of(args[7]).getFileName().toString());
            parameters.setDetachedContents(List.of(content));
        }
        DSSDocument extended;
        try {
            extended = service.extendDocument(new FileDocument(args[0]), parameters);
        } catch (RuntimeException refusal) {
            System.out.println("refused " + refusal.getMessage());
            System.exit(3);
            return;
        }
        extended.save(args[1]);
        System.out.println("augmented " + args[2]);
    }
}
