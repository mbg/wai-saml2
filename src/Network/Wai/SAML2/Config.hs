--------------------------------------------------------------------------------
-- SAML2 Middleware for WAI                                                   --
--------------------------------------------------------------------------------
-- This source code is licensed under the MIT license found in the LICENSE    --
-- file in the root directory of this source tree.                            --
--------------------------------------------------------------------------------

-- | Configuration types and smart constructors for the SAML2 middleware.
module Network.Wai.SAML2.Config (
    SAML2Config(..),
    saml2Config
) where

--------------------------------------------------------------------------------

import qualified Data.ByteString as BS
import qualified Data.Text as T
import Crypto.PubKey.RSA

--------------------------------------------------------------------------------

-- | Represents configurations for the SAML2 middleware.
data SAML2Config = SAML2Config {
    -- | The path relative to the root of the web application at which the
    -- middleware should listen for SAML2 assertions (e.g. /sso/assert).
    saml2AssertionPath :: !BS.ByteString,
    -- | The service provider's private key, used to decrypt data from
    -- the identity provider.
    saml2PrivateKey :: !PrivateKey,
    -- | The identity provider's public key, used to validate
    -- signatures.
    saml2PublicKey :: !PublicKey,
    -- | The name of the entity we expect assertions from. If this is set
    -- to 'Nothing', the issuer name is not validated.
    saml2ExpectedIssuer :: !(Maybe T.Text),
    -- | The URL we expect the SAML2 response to contain as destination.
    saml2ExpectedDestination :: !(Maybe T.Text),
    -- | A value indicating whether to disable time validity checks. This
    -- should not be set to 'True' in a production environment, but may
    -- be useful for testing purposes.
    saml2DisableTimeValidation :: !Bool,
    -- | Always decrypt assertions using 'saml2PrivateKey' and reject plaintext assertions.
    saml2RequireEncryptedAssertion :: !Bool
}

-- | 'saml2Config' @privateKey publicKey@ constructs a 'SAML2Config' value
-- with the most basic set of options possible using @privateKey@ as the
-- SP's private key and @publicKey@ as the IdP's public key. You should
-- almost certainly change the resulting settings.
saml2Config :: PrivateKey -> PublicKey -> SAML2Config
saml2Config privKey pubKey = SAML2Config{
    saml2AssertionPath = "/sso/assert",
    saml2PrivateKey = privKey,
    saml2PublicKey = pubKey,
    saml2ExpectedIssuer = Nothing,
    saml2ExpectedDestination = Nothing,
    saml2DisableTimeValidation = False,
    saml2RequireEncryptedAssertion = True
}

--------------------------------------------------------------------------------
