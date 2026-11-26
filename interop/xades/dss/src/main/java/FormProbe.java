import java.nio.file.*;
import java.util.List;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * A XAdES-BASELINE-B signature form made by DSS as its signature tests make
 * it, for xml-sec to validate. Arguments: PKCS#12 key store (alias "signer",
 * password "dss"), the form, a directory holding {@code document.xml},
 * {@code detached.txt} and {@code detached-2.txt}, the signing time in Unix
 * seconds and the output file. Forms: {@code parallel} (two enveloped
 * signatures over one document), {@code countersigned} and
 * {@code countersigned-nested} (an enveloping signature countersigned, and its
 * countersignature countersigned in turn), {@code detached-multiple} (one
 * detached signature over two files), {@code inclusive} (inclusive
 * canonicalization of SignedInfo and SignedProperties) and
 * {@code pretty-print} (DSS's indented serialization).
 */
public class FormProbe {
    public static void main(String[] args) throws Exception {
        var signer = Lifecycle.Signer.load(Path.of(args[0]));
        var data = Path.of(args[2]);
        long time = Long.parseLong(args[3]);
        var service = Lifecycle.signing();
        var document = Lifecycle.named(data.resolve("document.xml"));
        DSSDocument signed = switch (args[1]) {
            // DSS derives a signature's Id from its signing time and signer, so
            // the second signature is made a second later, as each of DSS's
            // tests signs at its own current time.
            case "parallel" -> {
                var first = sign(service, signer, time, "ENVELOPED", List.of(document), parameters -> {});
                yield sign(service, signer, time + 1, "ENVELOPED", List.of(first), parameters -> {});
            }
            case "countersigned" -> counter(
                service, signer, time + 1, enveloping(service, signer, time, document), false);
            case "countersigned-nested" -> {
                var once = counter(service, signer, time + 1, enveloping(service, signer, time, document), false);
                yield counter(service, signer, time + 2, once, true);
            }
            case "detached-multiple" -> sign(
                service,
                signer,
                time,
                "DETACHED",
                List.of(Lifecycle.named(data.resolve("detached.txt")), Lifecycle.named(data.resolve("detached-2.txt"))),
                parameters -> {});
            case "inclusive" -> sign(service, signer, time, "ENVELOPED", List.of(document), parameters -> {
                parameters.setSignedInfoCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
                parameters.setSignedPropertiesCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
            });
            case "pretty-print" -> sign(
                service, signer, time, "ENVELOPED", List.of(document), parameters -> parameters.setPrettyPrint(true));
            default -> throw new IllegalArgumentException("unknown form " + args[1]);
        };
        signed.save(args[4]);
    }

    interface Adjust {
        void apply(XAdESSignatureParameters parameters);
    }

    /** A B-B signature over {@code documents} in {@code packaging}, adjusted. */
    static DSSDocument sign(
            XAdESService service,
            Lifecycle.Signer signer,
            long time,
            String packaging,
            List<DSSDocument> documents,
            Adjust adjust)
            throws Exception {
        var algorithm = signer.sha256();
        var parameters = Lifecycle.baseline(new XAdESSignatureParameters(), signer, time, algorithm);
        parameters.setSignaturePackaging(SignaturePackaging.valueOf(packaging));
        adjust.apply(parameters);
        if (documents.size() == 1) {
            var toSign = service.getDataToSign(documents.get(0), parameters);
            return service.signDocument(
                documents.get(0), parameters, signer.token().sign(toSign, algorithm, signer.entry()));
        }
        var toSign = service.getDataToSign(documents, parameters);
        return service.signDocument(documents, parameters, signer.token().sign(toSign, algorithm, signer.entry()));
    }

    static DSSDocument enveloping(XAdESService service, Lifecycle.Signer signer, long time, DSSDocument document)
            throws Exception {
        return sign(service, signer, time, "ENVELOPING", List.of(document), parameters -> {});
    }

    /**
     * {@code signed} with a countersignature over its first signature, or
     * with {@code nested} over that signature's first countersignature.
     */
    static DSSDocument counter(
            XAdESService service, Lifecycle.Signer signer, long time, DSSDocument signed, boolean nested)
            throws Exception {
        var master = SignedDocumentValidator.fromDocument(signed).getSignatures().get(0);
        var target = nested ? master.getCounterSignatures().get(0) : master;
        var algorithm = signer.sha256();
        var parameters = Lifecycle.baseline(new XAdESCounterSignatureParameters(), signer, time, algorithm);
        parameters.setSignatureIdToCounterSign(target.getId());
        var toSign = service.getDataToBeCounterSigned(signed, parameters);
        return service.counterSignSignature(
            signed, parameters, signer.token().sign(toSign, algorithm, signer.entry()));
    }
}
