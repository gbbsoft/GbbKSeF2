using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using DataObject = System.Security.Cryptography.Xml.DataObject;

namespace TestKSeF2
{

    // Based on: https://stackoverflow.com/questions/50096199/c-sharp-how-to-properly-sign-message-with-xades-using-signedxml

    public static class KSeF_Xades
    {
        private const string SIGNATURE_ID = "Signature";
        private const string SIGNATURE_PROPERTIES_ID = "SignedProperties2";

        public const string URI_XmlDsigSignatureProperties = "http://uri.etsi.org/01903#SignedProperties";
        public const string URI_XadesProofOfApproval = "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval";
        public const string XADES_PREFIX = "xades";
        public const string NAMESPACE_XadesUrl = "http://uri.etsi.org/01903/v1.3.2#";

        public static XmlElement SignWithXAdES(X509Certificate2 signingCertificate, XmlDocument xmlDocument)
        {
            var signedXml = new SignedXml(xmlDocument); 
            //var signedXml = new XadesSignedXml(xmlDocument);
            //var signedXml = new CustomSignedXml(xmlDocument);
            signedXml.Signature.Id = SIGNATURE_ID;
            signedXml.SigningKey = signingCertificate.GetRSAPrivateKey();

            var signatureReference = new Reference { Uri = "", Id= "mainRefId" };
            signatureReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(signatureReference);

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(signingCertificate));
            signedXml.KeyInfo = keyInfo;

            AddXAdESProperties(xmlDocument, signedXml, signingCertificate);

            signedXml.ComputeSignature();
            //signedXml.ComputeSignature("ds");

            return signedXml.GetXml();
        }

        private static void AddXAdESProperties(XmlDocument document, /*XadesSignedXml*/ SignedXml SignedXml, X509Certificate2 signingCertificate)
        {
            var SignatureRef2 = new Reference
            {
                //Uri = $"#{SIGNATURE_PROPERTIES_ID}",
                Uri = "#ObjectRef1",
                Type = URI_XmlDsigSignatureProperties,
            };
            //SignatureRef2.AddTransform(new XmlDsigExcC14NTransform()); // it not accepted by KSeF (maybe)
            SignedXml.AddReference(SignatureRef2);

            // <Object>
            var objectNode = document.CreateElement("Object", SignedXml.XmlDsigNamespaceUrl);

            // <Object><QualifyingProperties>
            var qualifyingPropertiesNode = document.CreateElement(XADES_PREFIX, "QualifyingProperties", NAMESPACE_XadesUrl);
            qualifyingPropertiesNode.SetAttribute("Target", $"#{SIGNATURE_ID}");
            objectNode.AppendChild(qualifyingPropertiesNode);

            // <Object><QualifyingProperties><SignedProperties>
            var signedPropertiesNode = document.CreateElement(XADES_PREFIX, "SignedProperties", NAMESPACE_XadesUrl);
            signedPropertiesNode.SetAttribute("Id", SIGNATURE_PROPERTIES_ID);
            qualifyingPropertiesNode.AppendChild(signedPropertiesNode);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties>
            var signedSignaturePropertiesNode = document.CreateElement(XADES_PREFIX, "SignedSignatureProperties", NAMESPACE_XadesUrl);
            signedPropertiesNode.AppendChild(signedSignaturePropertiesNode);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties> </SigningTime>
            var signingTime = document.CreateElement(XADES_PREFIX, "SigningTime", NAMESPACE_XadesUrl);
            signingTime.InnerText = $"{DateTime.UtcNow.ToString("s")}Z";
            signedSignaturePropertiesNode.AppendChild(signingTime);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate>
            var signingCertificateNode = document.CreateElement(XADES_PREFIX, "SigningCertificate", NAMESPACE_XadesUrl);
            signedSignaturePropertiesNode.AppendChild(signingCertificateNode);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert>
            var certNode = document.CreateElement(XADES_PREFIX, "Cert", NAMESPACE_XadesUrl);
            signingCertificateNode.AppendChild(certNode);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><CertDigest>
            var certDigestNode = document.CreateElement(XADES_PREFIX, "CertDigest", NAMESPACE_XadesUrl);
            certNode.AppendChild(certDigestNode);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><CertDigest> </DigestMethod>
            var digestMethod = document.CreateElement("DigestMethod", SignedXml.XmlDsigNamespaceUrl);
            var digestMethodAlgorithmAtribute = document.CreateAttribute("Algorithm");
            digestMethodAlgorithmAtribute.InnerText = SignedXml.XmlDsigSHA1Url;
            digestMethod.Attributes.Append(digestMethodAlgorithmAtribute);
            certDigestNode.AppendChild(digestMethod);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><CertDigest> </DigestMethod>
            var digestValue = document.CreateElement("DigestValue", SignedXml.XmlDsigNamespaceUrl);
            digestValue.InnerText = Convert.ToBase64String(signingCertificate.GetCertHash());
            certDigestNode.AppendChild(digestValue);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><IssuerSerial>
            var issuerSerialNode = document.CreateElement(XADES_PREFIX, "IssuerSerial", NAMESPACE_XadesUrl);
            certNode.AppendChild(issuerSerialNode);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><IssuerSerial> </X509IssuerName>
            var x509IssuerName = document.CreateElement("X509IssuerName", SignedXml.XmlDsigNamespaceUrl);
            x509IssuerName.InnerText = signingCertificate.Issuer;
            issuerSerialNode.AppendChild(x509IssuerName);

            // <Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><IssuerSerial> </X509SerialNumber>
            var x509SerialNumber = document.CreateElement("X509SerialNumber", SignedXml.XmlDsigNamespaceUrl);
            x509SerialNumber.InnerText = ToDecimalString(signingCertificate.SerialNumber);
            issuerSerialNode.AppendChild(x509SerialNumber);

            //// XadesProofOfApproval
            //var signedDataObjectPropertiesNode = document.CreateElement(XadesPrefix, "SignedDataObjectProperties", XadesNamespaceUrl);
            //signedPropertiesNode.AppendChild(signedDataObjectPropertiesNode);
            //{

            //    // <Object><QualifyingProperties><SignedProperties><SignedDataObjectProperties><CommitmentTypeIndication>
            //    var commitmentTypeIndicationNode = document.CreateElement(XadesPrefix, "CommitmentTypeIndication", XadesNamespaceUrl);
            //    signedDataObjectPropertiesNode.AppendChild(commitmentTypeIndicationNode);

            //    // <Object><QualifyingProperties><SignedProperties><SignedDataObjectProperties><CommitmentTypeIndication><CommitmentTypeId>
            //    var commitmentTypeIdNode = document.CreateElement(XadesPrefix, "CommitmentTypeId", XadesNamespaceUrl);
            //    commitmentTypeIndicationNode.AppendChild(commitmentTypeIdNode);

            //    // <Object><QualifyingProperties><SignedProperties><SignedDataObjectProperties><CommitmentTypeIndication><CommitmentTypeId><Identifier>
            //    var identifierNode = document.CreateElement(XadesPrefix, "Identifier", XadesNamespaceUrl);
            //    identifierNode.InnerText = XadesProofOfApproval;
            //    commitmentTypeIdNode.AppendChild(identifierNode);

            //    // <Object><QualifyingProperties><SignedProperties><SignedDataObjectProperties><CommitmentTypeIndication><AllSignedDataObjects>
            //    var allSignedDataObjectsNode = document.CreateElement(XadesPrefix, "AllSignedDataObjects", XadesNamespaceUrl);
            //    commitmentTypeIndicationNode.AppendChild(allSignedDataObjectsNode);
            //}

            // DataObjectFormat
            var signedDataObjectPropertiesNode = document.CreateElement(XADES_PREFIX, "SignedDataObjectProperties", NAMESPACE_XadesUrl);
            signedPropertiesNode.AppendChild(signedDataObjectPropertiesNode);
            {

                var Node1 = document.CreateElement(XADES_PREFIX, "DataObjectFormat", NAMESPACE_XadesUrl);
                signedDataObjectPropertiesNode.AppendChild(Node1);
                var Attribute1 = document.CreateAttribute("ObjectReference");
                Attribute1.InnerText = "#mainRefId";
                Node1.Attributes.Append(Attribute1);

                var Node2 = document.CreateElement(XADES_PREFIX, "MimeType", NAMESPACE_XadesUrl);
                Node1.AppendChild(Node2);
                Node2.InnerText = "text/xml";
            }


            var dataObject = new DataObject();
            dataObject.Data = qualifyingPropertiesNode.SelectNodes(".");
            dataObject.Id = "ObjectRef1";
            SignedXml.AddObject(dataObject);
        }

        private static string ToDecimalString(string serialNumber)
        {
            BigInteger bi;

            if (BigInteger.TryParse(serialNumber, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bi))
            {
                return bi.ToString(CultureInfo.InvariantCulture);
            }
            else
            {
                return serialNumber;
            }
        }
    }

    /*
    public class XadesSignedXml : SignedXml
    {
        #region Public fields
        public XmlElement? PropertiesNode { get; set; }
        #endregion Public fields

        #region Private fields
        private readonly List<DataObject> _dataObjects = new List<DataObject>();
        #endregion Private fields

        #region Constructor
        public XadesSignedXml(XmlDocument document) : base(document) { }
        #endregion Constructor

        #region SignedXml
        public override XmlElement? GetIdElement(XmlDocument document, string idValue)
        {
            if (string.IsNullOrEmpty(idValue))
                return null;

            var xmlElement = base.GetIdElement(document, idValue);
            if (xmlElement != null)
                return xmlElement;

            foreach (var dataObject in _dataObjects)
            {
                var nodeWithSameId = findNodeWithAttributeValueIn(dataObject.Data, "Id", idValue);
                if (nodeWithSameId != null)
                    return nodeWithSameId;
            }

            if (KeyInfo != null)
            {
                var nodeWithSameId = findNodeWithAttributeValueIn(KeyInfo.GetXml().SelectNodes("."), "Id", idValue);
                if (nodeWithSameId != null)
                    return nodeWithSameId;
            }
            return null;
        }

        public new void AddObject(DataObject dataObject)
        {
            base.AddObject(dataObject);
            _dataObjects.Add(dataObject);
        }


        public XmlElement? findNodeWithAttributeValueIn(XmlNodeList? nodeList, string attributeName, string value)
        {
            if (nodeList==null || nodeList.Count == 0) return null;
            foreach (XmlNode node in nodeList)
            {
                XmlElement? nodeWithSameId = findNodeWithAttributeValueIn(node, attributeName, value);
                if (nodeWithSameId != null) return nodeWithSameId;
            }
            return null;
        }

        private XmlElement? findNodeWithAttributeValueIn(XmlNode node, string attributeName, string value)
        {
            string? attributeValueInNode = getAttributeValueInNodeOrNull(node, attributeName);
            if ((attributeValueInNode != null) && (attributeValueInNode.Equals(value))) return (XmlElement)node;
            return findNodeWithAttributeValueIn(node.ChildNodes, attributeName, value);
        }

        private string? getAttributeValueInNodeOrNull(XmlNode node, string attributeName)
        {
            if (node.Attributes != null)
            {
                XmlAttribute? attribute = node.Attributes[attributeName];
                if (attribute != null) return attribute.Value;
            }
            return null;
        }
        #endregion SignedXml
    }
    */


    internal sealed class CustomSignedXml : SignedXml
    {
        //XmlElement? obj = null;
        public CustomSignedXml(XmlDocument xml)
            : base(xml)
        {
        }

        public CustomSignedXml(XmlElement xmlElement)
            : base(xmlElement)
        {

        }

        public XmlElement GetXml(string prefix)
        {
            XmlElement e = this.GetXml();
            SetPrefix(prefix, e);
            return e;
        }

        public void ComputeSignature(string prefix)
        {
            this.BuildDigestedReferences();
            AsymmetricAlgorithm signingKey = this.SigningKey;
            if (signingKey == null)
            {
                throw new CryptographicException("Cryptography_Xml_LoadKeyFailed");
            }
            if (this.SignedInfo.SignatureMethod == null)
            {
                if (!(signingKey is DSA))
                {
                    if (!(signingKey is RSA))
                    {
                        throw new CryptographicException("Cryptography_Xml_CreatedKeyFailed");
                    }
                    if (this.SignedInfo.SignatureMethod == null)
                    {
                        //this.SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
                        //this.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                        this.SignedInfo.SignatureMethod = "RSA";
                    }
                }
                else
                {
                    this.SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
                }
            }
            SignatureDescription? description = CryptoConfig.CreateFromName(this.SignedInfo.SignatureMethod) as SignatureDescription;
            if (description == null)
            {
                throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");
            }
            HashAlgorithm? hash = description.CreateDigest();
            if (hash == null)
            {
                throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
            }
            this.GetC14NDigest(hash, prefix);
            this.m_signature.SignatureValue = description.CreateFormatter(signingKey).CreateSignature(hash);
        }

        private byte[] GetC14NDigest(HashAlgorithm hash, string prefix)
        {

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = false;
            XmlElement e = this.SignedInfo.GetXml();
            document.AppendChild(document.ImportNode(e, true));

            Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
            SetPrefix(prefix, document.DocumentElement); //Set the prefix before getting the HASH
            canonicalizationMethodObject.LoadInput(document);
            return canonicalizationMethodObject.GetDigestedOutput(hash);
        }

        private void BuildDigestedReferences()
        {
            Type t = typeof(SignedXml);
            MethodInfo m = t.GetMethod("BuildDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance)!;
            m.Invoke(this, new object[] { });
        }

        private void SetPrefix(string prefix, XmlNode? node)
        {
            if (node == null) return;
            foreach (XmlNode n in node.ChildNodes)
                SetPrefix(prefix, n);
            node.Prefix = prefix;
        }
    }

}
