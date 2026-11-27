import java.nio.file.*;
import java.security.KeyStore;
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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
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

    /**
     * A signer's key entry (alias "signer") in its PKCS#12 store: DSS's own
     * token signs with it, for every algorithm DSS supports.
     */
    record Signer(Pkcs12SignatureToken token, DSSPrivateKeyEntry entry) {
        static Signer load(Path store) throws Exception {
            var token = new Pkcs12SignatureToken(store.toFile(), new KeyStore.PasswordProtection(PASSWORD));
            return new Signer(token, token.getKey("signer"));
        }

        List<CertificateToken> chain() {
            return List.of(entry.getCertificateChain());
        }

        /** The signer's key algorithm with SHA-256. */
        SignatureAlgorithm sha256() {
            var encryption = EncryptionAlgorithm.forKey(entry.getCertificate().getPublicKey());
            return SignatureAlgorithm.getAlgorithm(encryption, DigestAlgorithm.SHA256);
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
     * INTERNALLY_DETACHED), signed with {@code algorithm} at Unix time
     * {@code time}. References are digested with SHA-256 whatever the
     * signature's own digest, as DSS's Ed448 tests do for SHAKE256.
     */
    static DSSDocument sign(
            XAdESService service,
            Signer signer,
            String packaging,
            DSSDocument data,
            long time,
            SignatureAlgorithm algorithm)
            throws Exception {
        var parameters = baseline(new XAdESSignatureParameters(), signer, time, algorithm);
        parameters.setSignaturePackaging(SignaturePackaging.valueOf(packaging));
        var toSign = service.getDataToSign(data, parameters);
        return service.signDocument(data, parameters, signer.token().sign(toSign, algorithm, signer.entry()));
    }

    /**
     * {@code parameters} set for a XAdES-BASELINE-B signature by
     * {@code signer} with {@code algorithm} at Unix time {@code time}, the
     * references digested with SHA-256.
     */
    static <P extends XAdESSignatureParameters> P baseline(
            P parameters, Signer signer, long time, SignatureAlgorithm algorithm) {
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        // The certificate first: setting it resets the encryption algorithm
        // to its key's, which would turn RSASSA-PSS back into PKCS#1 v1.5.
        parameters.setSigningCertificate(signer.chain().get(0));
        parameters.setCertificateChain(signer.chain());
        parameters.setDigestAlgorithm(algorithm.getDigestAlgorithm());
        parameters.setEncryptionAlgorithm(algorithm.getEncryptionAlgorithm());
        parameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.bLevel().setSigningDate(Date.from(Instant.ofEpochSecond(time)));
        return parameters;
    }

    /**
     * The verifier that trusts only {@code anchor} and fetches nothing. With
     * {@code evidence}, a directory of DER certificates (*.cer), CRLs (*.crl)
     * and OCSP responses (*.ocsp), those are its only sources; without it the
     * document's own material is.
     */
    static CommonCertificateVerifier verifier(byte[] anchor, Path evidence) throws Exception {
        return verifier(List.of(anchor), evidence);
    }

    /** As {@link #verifier(byte[], Path)}, trusting every one of {@code anchors}. */
    static CommonCertificateVerifier verifier(List<byte[]> anchors, Path evidence) throws Exception {
        var verifier = new CommonCertificateVerifier();
        verifier.setAIASource(null);
        var trusted = new CommonTrustedCertificateSource();
        for (var index = 0; index < anchors.size(); index++) {
            try {
                trusted.addCertificate(DSSUtils.loadCertificate(anchors.get(index)));
            } catch (RuntimeException error) {
                throw new IllegalArgumentException("anchor " + index + " cannot be loaded", error);
            }
        }
        verifier.setTrustedCertSources(trusted);
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
        return extend(service, input, level, detached == null ? List.of() : List.of(detached));
    }

    /** As the single-content form, with every content the references name. */
    static DSSDocument extend(XAdESService service, DSSDocument input, String level, List<DSSDocument> detached) {
        var parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.valueOf("XAdES_BASELINE_" + level));
        if (!detached.isEmpty()) {
            parameters.setDetachedContents(detached);
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
        return validate(document, verifier, time, level, detached == null ? List.of() : List.of(detached));
    }

    /** As {@link #validate(DSSDocument, CommonCertificateVerifier, long, ValidationLevel, DSSDocument)}
     * with every content the signature's detached references name. */
    static Reports validate(
            DSSDocument document,
            CommonCertificateVerifier verifier,
            long time,
            ValidationLevel level,
            List<DSSDocument> detached) {
        var validator = SignedDocumentValidator.fromDocument(document);
        validator.setCertificateVerifier(verifier);
        if (!detached.isEmpty()) {
            validator.setDetachedContents(detached);
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
