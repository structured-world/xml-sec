use super::declarations;
use xml_sec::xmldsig::{DigestAlgorithm, SignatureAlgorithm};

/// A signature whose `ds:Object` carries elements named like the ones of its
/// `ds:SignedInfo`, in a foreign namespace and in `ds` itself.
const DECOYED: &str = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#o">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AA==</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
  <ds:Object Id="o">
    <x:SignatureMethod xmlns:x="urn:other" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:SignedInfo>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Object>
</ds:Signature>"##;

#[test]
fn the_declared_algorithms_are_read_from_the_signatures_own_signed_info() {
    // Only the signature's own ds:SignedInfo declares its algorithms (XMLDSig
    // 1.1 section 4.4): a later element of the same name elsewhere must not
    // replace them, or the compared profile's constraints judge another
    // algorithm than the one the signature uses.
    let found = declarations(DECOYED);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].method, Some(SignatureAlgorithm::RsaSha1));
    assert_eq!(found[0].digests, [Some(DigestAlgorithm::Sha1)]);
}
