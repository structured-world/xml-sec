import java.nio.file.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Date;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * A XAdES-BASELINE-B signature made by DSS, the start of the lifecycle that
 * xml-sec continues. Arguments: PKCS#12 key store (alias "signer", password
 * "dss"), packaging (ENVELOPED, ENVELOPING, DETACHED or INTERNALLY_DETACHED),
 * the data to sign, the signing time in Unix seconds and the output file.
 */
public class SignProbe {
    public static void main(String[] args) throws Exception {
        char[] password = "dss".toCharArray();
        var store = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(Path.of(args[0]))) {
            store.load(input, password);
        }
        var key = (PrivateKey) store.getKey("signer", password);
        var chain = new java.util.ArrayList<CertificateToken>();
        for (var certificate : store.getCertificateChain("signer")) {
            chain.add(DSSUtils.loadCertificate(certificate.getEncoded()));
        }
        var parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.valueOf(args[1]));
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(chain.get(0));
        parameters.setCertificateChain(chain);
        parameters.bLevel().setSigningDate(Date.from(Instant.ofEpochSecond(Long.parseLong(args[3]))));
        var document = new FileDocument(args[2]);
        document.setName(Path.of(args[2]).getFileName().toString());
        var service = new XAdESService(new CommonCertificateVerifier());
        var data = service.getDataToSign(document, parameters);
        var encryption = EncryptionAlgorithm.forKey(chain.get(0).getPublicKey());
        var algorithm = SignatureAlgorithm.getAlgorithm(encryption, DigestAlgorithm.SHA256);
        var signer = Signature.getInstance(algorithm.getJCEId());
        signer.initSign(key);
        signer.update(data.getBytes());
        // A JCE ECDSA signature is DER, the form DSS converts to XMLDSig's r || s.
        var value = new SignatureValue(algorithm, signer.sign());
        service.signDocument(document, parameters, value).save(args[4]);
    }
}
