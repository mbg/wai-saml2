-------------------------------------------------------------------------------
-- SAML2 Middleware for WAI                                                  --
-------------------------------------------------------------------------------
-- This source code is licensed under the MIT license found in the LICENSE   --
-- file in the root directory of this source tree.                           --
-------------------------------------------------------------------------------

-- | Defines types and functions for SP-initiated SSO. Use `issueAuthnRequest`
-- to initialise an `AuthnRequest` value which stores the parameters for the
-- authentication request you wish to issue to the IdP. You can update this
-- value as required.
--
-- Use `renderBase64` to render the request for use with a HTTP POST binding [1], or
-- `renderUrlEncodingDeflate` for HTTP redirect binding[2] respectively.
-- You may wish to read
-- the [SAML2 overview for this process](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.2.SP-Initiated%20SSO:%20%20Redirect/POST%20Bindings|outline).
--
-- * [1] https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf#page=21
--   Section 3.5 HTTP POST Binding
-- * [2] https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf#page=15
--   Section 3.4 HTTP Redirect Binding
module Network.Wai.SAML2.Request (
    AuthnRequest(..),
    issueAuthnRequest,
    renderBase64,
    renderUrlEncodingDeflate,
    renderXML,
) where

-------------------------------------------------------------------------------

import Crypto.Random

import Data.Time.Clock
import Data.Time.Format

import Network.Wai.SAML2.XML

import Text.XML

import qualified Codec.Compression.Zlib.Raw as Deflate
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Network.HTTP.Types (urlEncode)

-------------------------------------------------------------------------------

-- | Parameters for SP-initiated SSO
data AuthnRequest
    = AuthnRequest {
        -- | The time at which 'AuthnRequest' was created.
        authnRequestTimestamp :: !UTCTime
        -- | Unique identifier for 'AuthnRequest' which should be preserved
        -- by the IdP in its response.
    ,   authnRequestID :: !T.Text
        -- | SP Entity ID
    ,   authnRequestIssuer :: !T.Text
        -- | Allow IdP to generate a new identifier
    ,   authnRequestAllowCreate :: !Bool
        -- | The URI reference corresponding to a name identifier format
    ,   authnRequestNameIDFormat :: !T.Text
    }
    deriving (Eq, Show)

-- | Creates a default 'AuthnRequest' with the current timestamp and a
-- randomly-generated ID.
issueAuthnRequest
    :: T.Text -- ^ SP Entity ID
    -> IO AuthnRequest
issueAuthnRequest authnRequestIssuer = do
    authnRequestTimestamp <- getCurrentTime
    -- Azure AD does not accept an id starting with a number
    -- https://learn.microsoft.com/en-us/azure/active-directory/develop/single-sign-on-saml-protocol
    authnRequestID <- ("id" <>) . T.decodeUtf8 . Base16.encode <$> getRandomBytes 16
    pure AuthnRequest{
        authnRequestAllowCreate = True
    ,   authnRequestNameIDFormat =
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    ,   ..
    }

-- | Renders an `AuthnRequest` for SP initiated SSO according to
-- @urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE@ and suitable for
-- use with HTTP Redirect binding
--
-- The value should be sent as a query parameter named @SAMLRequest@
renderUrlEncodingDeflate :: AuthnRequest -> B.ByteString
renderUrlEncodingDeflate request =
    urlEncode True $ Base64.encode $ BL.toStrict $ Deflate.compress $ renderXML request

-- | Renders and base64-encodes an `AuthnRequest` for SP initiated SSO suitable
-- for use with HTTP POST binding
--
-- If used in an HTTP POST binding, the value should be sent as an invisible
-- form control named @SAMLRequest@
renderBase64 :: AuthnRequest -> B.ByteString
renderBase64 request = Base64.encode $ BL.toStrict $ renderXML request

-- | Render an `AuthnRequest` as XML
renderXML :: AuthnRequest -> BL.ByteString
renderXML AuthnRequest{..} =
    renderLBS def $
    Document{
        documentPrologue = Prologue [] Nothing []
    ,   documentRoot = root
    ,   documentEpilogue = []
    }
    where
        timestamp = T.pack $
            formatTime defaultTimeLocale timeFormat authnRequestTimestamp
        root = Element
            (saml2pName "AuthnRequest")
            (Map.fromList
                [ ("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
                , ("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
                , ("ID", authnRequestID)
                , ("Version", "2.0")
                , ("IssueInstant", timestamp)
                , ("AssertionConsumerServiceIndex", "1")
                ])
            [NodeElement issuer, NodeElement nameIdPolicy]
        issuer = Element
            (saml2Name "Issuer")
            mempty
            [NodeContent authnRequestIssuer]
        nameIdPolicy = Element
            (saml2pName "NameIDPolicy")
            (Map.fromList
                [ ("allowCreate"
                    , if authnRequestAllowCreate then "true" else "false")
                , ("Format", authnRequestNameIDFormat)
                ])
            []

-------------------------------------------------------------------------------
