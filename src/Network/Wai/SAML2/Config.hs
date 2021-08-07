--------------------------------------------------------------------------------
-- SAML2 Middleware for WAI                                                   --
--------------------------------------------------------------------------------
-- This source code is licensed under the MIT license found in the LICENSE    --
-- file in the root directory of this source tree.                            --
--------------------------------------------------------------------------------

-- | Configuration types and smart constructors for the SAML2 middleware.
module Network.Wai.SAML2.Config (
    SAML2CfgFlags(..),
    SAML2Config(..),
    saml2Config,
    saml2PlainTextConfig,
    HasSaml2Config,
    SpPrivateKey(..)
) where 

--------------------------------------------------------------------------------

import qualified Data.ByteString as BS
import qualified Data.Text as T
import Crypto.PubKey.RSA

--------------------------------------------------------------------------------

-- | The constructors of this kind enumerate configuration options.
data SAML2CfgFlags
    -- | If this flag is set, assertions are expected to be unencyrpted.
    = PlainTextAssertions

-- | This type family combines type-level @elem@ and @if@ so that 
-- `CfgHasFlag` @flag opts t f@ will evaluate to @t@ if @opts@ contains
-- @flag@ or to @f@ otherwise.
type family CfgHasFlag 
    (flag :: SAML2CfgFlags) 
    (opts :: [SAML2CfgFlags]) 
    (tru :: k)
    (fls :: k) :: k where
    CfgHasFlag f '[] tru fls = fls
    CfgHasFlag f (f ': opts) tru fls = tru
    CfgHasFlag f (_ ': opts) tru fls = CfgHasFlag f opts tru fls

type CfgPrivateKey opts = 
    CfgHasFlag 'PlainTextAssertions opts () PrivateKey

-- | Represents configurations for the SAML2 middleware.
data SAML2Config opts = SAML2Config {
    -- | The path relative to the root of the web application at which the
    -- middleware should listen for SAML2 assertions (e.g. /sso/assert).
    saml2AssertionPath :: !BS.ByteString,
    -- | The service provider's private key, used to decrypt data from 
    -- the identity provider.
    saml2PrivateKey :: !(CfgPrivateKey opts),
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
    saml2DisableTimeValidation :: !Bool
}

-- | 'saml2Config' @privateKey publicKey@ constructs a 'SAML2Config' value
-- with the most basic set of options possible using @privateKey@ as the 
-- SP's private key and @publicKey@ as the IdP's public key. You should 
-- almost certainly change the resulting settings.
saml2Config :: PrivateKey -> PublicKey -> SAML2Config '[]
saml2Config privKey pubKey = SAML2Config{
    saml2AssertionPath = "/sso/assert",
    saml2PrivateKey = privKey,
    saml2PublicKey = pubKey,
    saml2ExpectedIssuer = Nothing,
    saml2ExpectedDestination = Nothing,
    saml2DisableTimeValidation = False
}

-- | `saml2PlainTextConfig` @publicKey@ constructs a `SAML2Config` value with 
-- the most basic set of options possible. Unlike `saml2Config`, we do not 
-- require a private key for the SP here and instead expect assertions to be
-- delivered to us in plain text by the identity provider.
saml2PlainTextConfig :: PublicKey -> SAML2Config '[PlainTextAssertions]
saml2PlainTextConfig pubKey = SAML2Config{
    saml2AssertionPath = "/sso/assert",
    saml2PrivateKey = (),
    saml2PublicKey = pubKey,
    saml2ExpectedIssuer = Nothing,
    saml2ExpectedDestination = Nothing,
    saml2DisableTimeValidation = False
}

-- | A constraint alias for all constraints we can place on the SAML2
-- configuration. This is primarily used so that we can write safe functions
-- which can retrieve whatever configuration components are available based
-- on the type-level configuration.
type HasSaml2Config opts = 
    ( SpPrivateKey opts
    )

class SpPrivateKey opts where
    -- | `spPrivateKey` @config@ retrieves the SP's private key, if encrypted
    -- assertions are used.
    spPrivateKey :: SAML2Config opts -> Maybe PrivateKey

instance SpPrivateKey (PlainTextAssertions ': os) where
    spPrivateKey _ = Nothing

instance SpPrivateKey '[] where
    spPrivateKey cfg = Just (saml2PrivateKey cfg)

--------------------------------------------------------------------------------
