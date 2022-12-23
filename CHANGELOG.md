# Changelog for `wai-saml2`

## Unreleased

* Split `validateResponse` into `decodeResponse` and `validateSAMLResponse` ([#31](https://github.com/mbg/wai-saml2/pull/31) by [@fumieval](https://github.com/fumieval))
* Exported `NameID` (formerly `NameId`), and renamed `subjectNameId` to `subjectNameID`
* Support GHC 9.4 ([#36](https://github.com/mbg/wai-saml2/pull/36) by [@mbg](https://github.com/mbg))
* Add new module `Network.Wai.SAML2.Request` with `AuthnRequest` generation for SP-initiated login flow ([#19](https://github.com/mbg/wai-saml2/pull/19) by [@fumieval](https://github.com/fumieval))
* Changed the `saml2PrivateKey` field to be optional and added `saml2ConfigNoEncryption` which takes a `PublicKey` only

## 0.3

* Improve parse error handling and make `encryptedKeyData` optional ([#11](https://github.com/mbg/wai-saml2/pull/11) by [@Philonous](https://github.com/Philonous))
* Add `subjectNameId` to `Subject` type ([#13](https://github.com/mbg/wai-saml2/pull/13) by [@kdxu](https://github.com/kdxu))
* Support the response format used by Okta, in which the `EncryptedAssertion` element is structured differently ([#12](https://github.com/mbg/wai-saml2/pull/12) by [@fumieval](https://github.com/fumieval))

## 0.2.1.3

* Metadata updates.

## 0.2.1.2

No changes.

## 0.2.1.1

* Export `Result` type from `Network.Wai.SAML2` module.

## 0.2.1

* Fix missing export of `relayStateKey` and change its type.

## 0.2.0

* Added parsing for RelayState from form data, as sent by e.g. Shibboleth when a `target` query string parameter is passed to the unsolicited SSO endpoint.

## 0.1.0

* Initial release
