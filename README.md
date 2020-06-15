Create SAML assertions.

Supports both SAML 1.1 and SAML 2.0 tokens

### Usage

```js
var saml11 = require('saml').Saml11;

var options = {
  cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
  key: fs.readFileSync(__dirname + '/test-auth0.key'),
  issuer: 'urn:issuer',
  lifetimeInSeconds: 600,
  audiences: 'urn:myapp',
  attributes: {
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar'
  },
  nameIdentifier: 'foo',
  sessionIndex: '_faed468a-15a0-4668-aed6-3d9c478cc8fa'
};

var signedAssertion = saml11.create(options);
```

Everything except the cert and key is optional.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section.

## Author

[Auth0](auth0.com) (Modifications by Wouter de Bruijn)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
