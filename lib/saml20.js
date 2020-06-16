
var utils = require('./utils'),
    Parser = require('xmldom').DOMParser,
    SignedXml = require('xml-crypto').SignedXml,
    xmlenc = require('xml-encryption'),
    moment = require('moment'),
    xmlNameValidator = require('xml-name-validator'),
    is_uri = require('valid-url').is_uri;

var fs = require('fs');
var path = require('path');
const { sign } = require('crypto');
var saml20 = fs.readFileSync(path.join(__dirname, 'saml20.template')).toString();

var algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};

function getAttributeType(value){
  switch(typeof value) {
    case "string":
      return 'xs:string';
    case "boolean":
      return 'xs:boolean';
    case "number":
      // Maybe we should fine-grain this type and check whether it is an integer, float, double xsi:types
      return 'xs:double';
    default:
      return 'xs:anyType';
  }
}

function getElementsFromObject(doc, main, nodes){
  if(typeof nodes !== 'object') {
    main.textContent = nodes;
  } else {
    for (let [key, value] of Object.entries(nodes)) {
      let element = doc.createElement(key);

      if(value['_attributes']) {
        for (let [attrkey, attrvalue] of Object.entries(value['_attributes'])) {
          element.setAttribute(attrkey, attrvalue);
        }

        delete value['_attributes'];
      }

      getElementsFromObject(doc, element, value);

      main.appendChild(element);
    }
  }
}

function getNameFormat(name){
  if (is_uri(name)){
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
  }

  //  Check that the name is a valid xs:Name -> https://www.w3.org/TR/xmlschema-2/#Name
  //  xmlNameValidate.name takes a string and will return an object of the form { success, error },
  //  where success is a boolean
  //  if it is false, then error is a string containing some hint as to where the match went wrong.
  if (xmlNameValidator.name(name).success){
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';
  }

  // Default value
  return 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
}

exports.create = function(options, callback) {
  if (!options.key)
    throw new Error('Expect a private key in pem format');

  if (!options.cert)
    throw new Error('Expect a public key cert in pem format');

  options.asXmlMap = (typeof options.asXmlMap !== 'undefined') ? options.asXmlMap : false;

  options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  options.digestAlgorithm = options.digestAlgorithm || 'sha256';

  options.includeAttributeNameFormat = (typeof options.includeAttributeNameFormat !== 'undefined') ? options.includeAttributeNameFormat : true;
  options.typedAttributes = (typeof options.typedAttributes !== 'undefined') ? options.typedAttributes : true;

  // 0.10.1 added prefix, but we want to name it signatureNamespacePrefix - This is just to keep supporting prefix
  options.signatureNamespacePrefix = options.signatureNamespacePrefix || options.prefix;
  options.signatureNamespacePrefix = typeof options.signatureNamespacePrefix === 'string' ? options.signatureNamespacePrefix : '' ;

  var cert = utils.pemToCert(options.cert);

  var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[options.signatureAlgorithm], idAttribute: 'ID' });
  sig.addReference("//*[local-name(.)='Assertion']",
                  ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
                  algorithms.digest[options.digestAlgorithm]);

  sig.signingKey = options.key;

  sig.keyInfoProvider = {
    getKeyInfo: function (key, prefix) {
      prefix = prefix ? prefix + ':' : prefix;
      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + cert + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
    }
  };

  var doc;
  try {
    doc = new Parser().parseFromString(saml20.toString());
  } catch(err){
    return utils.reportError(err, callback);
  }

  doc.documentElement.setAttribute('ID', '_' + (options.uid || utils.uid(32)));
  doc.documentElement.setAttribute('xmlns', 'urn:oasis:names:tc:SAML:2.0:assertion');

  if (options.issuer) {
    var issuer = doc.documentElement.getElementsByTagName('Issuer');
    issuer[0].textContent = options.issuer;
  }

  var now = moment.utc();
  doc.documentElement.setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  var conditions = doc.documentElement.getElementsByTagName('Conditions');
  var confirmationData = doc.documentElement.getElementsByTagName('SubjectConfirmationData');

  if (options.lifetimeInSeconds) {
    conditions[0].setAttribute('NotBefore', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    conditions[0].setAttribute('NotOnOrAfter', now.clone().add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

    confirmationData[0].setAttribute('NotOnOrAfter', now.clone().add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  }

  if (options.audiences) {
    var audienceRestriction = doc.createElement('AudienceRestriction');
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElement('Audience');
      element.textContent = audience;
      audienceRestriction.appendChild(element);
    });

    conditions[0].appendChild(audienceRestriction);
  }

  if (options.recipient)
    confirmationData[0].setAttribute('Recipient', options.recipient);

  if (options.inResponseTo)
    confirmationData[0].setAttribute('InResponseTo', options.inResponseTo);

  if (options.attributes) {
    var statement = doc.createElement('AttributeStatement');
    doc.documentElement.appendChild(statement);
    Object.keys(options.attributes).forEach(function(prop) {
      if(typeof options.attributes[prop] === 'undefined') return;
      // <Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/claims/identity">
      //    <AttributeValue>Foo Bar</AttributeValue>
      // </Attribute>
      var attributeElement = doc.createElement('Attribute');
      attributeElement.setAttribute('Name', prop);

      if (options.includeAttributeNameFormat) {
        attributeElement.setAttribute('NameFormat', getNameFormat(prop));
      }

      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        // Check by type, becase we want to include false values
        if (typeof value !== 'undefined') {
          // Ignore undefined values in Array
          var valueElement = doc.createElement('AttributeValue');

          if(!options.asXmlMap) {
            valueElement.textContent = value;
          } else {
            getElementsFromObject(doc, valueElement, value);
          }

          attributeElement.appendChild(valueElement);
        }
      });

      if (values && values.filter(function(i){ return typeof i !== 'undefined'; }).length > 0) {
        // Attribute must have at least one AttributeValue
        statement.appendChild(attributeElement);
      }
    });
  }

  doc.getElementsByTagName('AuthnStatement')[0]
    .setAttribute('AuthnInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

  if (options.sessionIndex) {
    doc.getElementsByTagName('AuthnStatement')[0]
      .setAttribute('SessionIndex', options.sessionIndex);
  }

  var nameID = doc.documentElement.getElementsByTagName('NameID')[0];

  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;
  }

  if (options.nameIdentifierFormat) {
    nameID.setAttribute('Format', options.nameIdentifierFormat);
  }

  if( options.authnContextClassRef ) {
    var authnCtxClassRef = doc.getElementsByTagName('AuthnContextClassRef')[0];
    authnCtxClassRef.textContent = options.authnContextClassRef;
  }

  var token = utils.removeWhitespace(doc.toString());

  // Remove any extra namespacing
  let cleantoken = token.replace('Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"', 'INTERMEDIATE_NS')
                        .replace(/ xmlns="urn:oasis:names:tc:SAML:2\.0:assertion"/g, '')
                        .replace('INTERMEDIATE_NS', 'Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"');

  console.log(cleantoken);
  var signed;
  try {
    var opts = {
      location: {
        reference: options.xpathToNodeBeforeSignature || "//*[local-name(.)='Issuer']",
        action: 'after'
      },
      prefix: options.signatureNamespacePrefix
    };

    sig.computeSignature(cleantoken, opts);
    signed = sig.getSignedXml();
    console.log(signed);
    signed = signed.replace('Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"', 'INTERMEDIATE_NS');
    console.log(signed);
    signed = signed.replace(/ xmlns="urn:oasis:names:tc:SAML:2\.0:assertion"/g, '');
    console.log(signed);
    signed = signed.replace('INTERMEDIATE_NS', 'Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"');
    console.log(signed);
  } catch(err){
    return utils.reportError(err, callback);
  }

  if (!options.encryptionCert) {
    if (callback)
      return callback(null, signed);
    else
      return signed;
  }


  var encryptOptions = {
    rsa_pub: options.encryptionPublicKey,
    pem: options.encryptionCert,
    encryptionAlgorithm: options.encryptionAlgorithm || 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    keyEncryptionAlgorighm: options.keyEncryptionAlgorighm || 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
  };

  xmlenc.encrypt(signed, encryptOptions, function(err, encrypted) {
    if (err) return callback(err);
    encrypted = '<EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' + encrypted + '</EncryptedAssertion>';
    callback(null, utils.removeWhitespace(encrypted));
  });
};
