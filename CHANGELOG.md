# Changelog for `wai-saml2`

## Unreleased

* Added `decodeResponse` and `validateSAMLResponse`
* Exported `NameID` (formerly `NameId`), and renamed `subjectNameId` to `subjectNameID`

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
