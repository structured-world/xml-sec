import java.nio.file.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * The DSS lifecycle operations the probes and the benchmark harness share:
 * nothing is fetched, every key, anchor, status and token is supplied.
 */
final class Lifecycle {
    /** The password of every PKCS#12 store of the run. */
    static final char[] PASSWORD = "dss".toCharArray();

    private Lifecycle() {}

    /** A signer's private key and certificate chain from its PKCS#12 store (alias "signer"). */
    record Signer(PrivateKey key, List<CertificateToken> chain) {
        static Signer load(Path store) throws Exception {
            var keys = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(store)) {
                keys.load(input, PASSWORD);
            }
            var chain = new ArrayList<CertificateToken>();
            for (var certificate : keys.getCertificateChain("signer")) {
                chain.add(DSSUtils.loadCertificate(certificate.getEncoded()));
            }
            return new Signer((PrivateKey) keys.getKey("signer", PASSWORD), chain);
        }
    }

    /** A file supplied by its name, as a detached reference names it. */
    static DSSDocument named(Path file) {
        var document = new FileDocument(file.toFile());
        document.setName(file.getFileName().toString());
        return document;
    }

    /** The signing service, nothing fetched: B-B creation needs no evidence. */
    static XAdESService signing() {
        return new XAdESService(new CommonCertificateVerifier());
    }

    /**
     * A XAdES-BASELINE-B signature by {@code service} over {@code data} in
     * {@code packaging} (ENVELOPED, ENVELOPING, DETACHED or
     * INTERNALLY_DETACHED), signed at Unix time {@code time}.
     */
    static DSSDocument sign(XAdESService service, Signer signer, String packaging, DSSDocument data, long time)
            throws Exception {
        var parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.valueOf(packaging));
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(signer.chain().get(0));
        parameters.setCertificateChain(signer.chain());
        parameters.bLevel().setSigningDate(Date.from(Instant.ofEpochSecond(time)));
        var toSign = service.getDataToSign(data, parameters);
        var encryption = EncryptionAlgorithm.forKey(signer.chain().get(0).getPublicKey());
        var algorithm = SignatureAlgorithm.getAlgorithm(encryption, DigestAlgorithm.SHA256);
        var jce = Signature.getInstance(algorithm.getJCEId());
        jce.initSign(signer.key());
        jce.update(toSign.getBytes());
        // A JCE ECDSA signature is DER, the form DSS converts to XMLDSig's r || s.
        return service.signDocument(data, parameters, new SignatureValue(algorithm, jce.sign()));
    }

    /**
     * The verifier that trusts only {@code anchor} and fetches nothing. With
     * {@code evidence}, a directory of DER certificates (*.cer), CRLs (*.crl)
     * and OCSP responses (*.ocsp), those are its only sources; without it the
     * document's own material is.
     */
    static CommonCertificateVerifier verifier(byte[] anchor, Path evidence) throws Exception {
        var verifier = new CommonCertificateVerifier();
        verifier.setAIASource(null);
        var anchors = new CommonTrustedCertificateSource();
        anchors.addCertificate(DSSUtils.loadCertificate(anchor));
        verifier.setTrustedCertSources(anchors);
        var certificates = new CommonCertificateSource();
        List<DSSDocument> crls = new ArrayList<>();
        List<DSSDocument> responses = new ArrayList<>();
        if (evidence != null) {
            try (var files = Files.list(evidence)) {
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
        }
        verifier.setAdjunctCertSources(certificates);
        verifier.setCrlSource(crls.isEmpty() ? null : new ExternalResourcesCRLSource(crls.toArray(DSSDocument[]::new)));
        verifier.setOcspSource(responses.isEmpty() ? null : new ExternalResourcesOCSPSource(responses.toArray(DSSDocument[]::new)));
        return verifier;
    }

    /** The run's TSA: PKCS#12 (alias "tsa"), its policy, tokens at Unix time {@code time}. */
    static KeyEntityTSPSource tsa(Path store, long time) throws Exception {
        var tsa = new KeyEntityTSPSource(store.toFile(), "PKCS12", PASSWORD, "tsa", PASSWORD);
        tsa.setTsaPolicy("1.3.6.1.4.1.13762.3");
        tsa.setProductionTime(Date.from(Instant.ofEpochSecond(time)));
        return tsa;
    }

    /** The augmentation service of {@code verifier} with timestamps from {@code tsa}. */
    static XAdESService augmenting(CommonCertificateVerifier verifier, TSPSource tsa) {
        var service = new XAdESService(verifier);
        service.setTspSource(tsa);
        return service;
    }

    /**
     * {@code input} augmented by {@code service} to {@code level} (T, LT or
     * LTA; LTA on a B-LTA signature renews it), with the content a detached
     * reference names.
     */
    static DSSDocument extend(XAdESService service, DSSDocument input, String level, DSSDocument detached) {
        var parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.valueOf("XAdES_BASELINE_" + level));
        if (detached != null) {
            parameters.setDetachedContents(List.of(detached));
        }
        return service.extendDocument(input, parameters);
    }

    /**
     * The reports of {@code document} at {@code level} and Unix time
     * {@code time}, through {@code verifier}: {@code verifier(anchor, null)}
     * reads only the document's own material.
     */
    static Reports validate(
            DSSDocument document,
            CommonCertificateVerifier verifier,
            long time,
            ValidationLevel level,
            DSSDocument detached) {
        var validator = SignedDocumentValidator.fromDocument(document);
        validator.setCertificateVerifier(verifier);
        if (detached != null) {
            validator.setDetachedContents(List.of(detached));
        }
        validator.setValidationTime(Date.from(Instant.ofEpochSecond(time)));
        validator.setValidationLevel(level);
        return validator.validateDocument();
    }

    /** One line per signature: its format, indication, subindication and errors. */
    static String lines(Reports reports) {
        var simple = reports.getSimpleReport();
        var lines = new StringBuilder();
        for (var id : simple.getSignatureIdList()) {
            lines.append(String.format(
                "%s format=%s indication=%s subindication=%s errors=%s%n",
                id,
                simple.getSignatureFormat(id),
                simple.getIndication(id),
                simple.getSubIndication(id),
                simple.getAdESValidationErrors(id).stream().map(message -> message.getValue()).toList()));
        }
        return lines.toString();
    }
}
