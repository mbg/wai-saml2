-------------------------------------------------------------------------------
-- SAML2 Middleware for WAI                                                  --
-------------------------------------------------------------------------------
-- This source code is licensed under the MIT license found in the LICENSE   --
-- file in the root directory of this source tree.                           --
-------------------------------------------------------------------------------

-- | Defines types and functions for SP-initiated SSO. Use `issueAuthnRequest`
-- to initialise an `AuthnRequest` value which stores the parameters for the
-- authentication request you wish to issue to the IdP. You can update this
-- value as required. Then use `renderAuthnRequest` to format the
-- `AuthnRequest` as XML and render it to a `B.ByteString` containing a
-- base64-encoded representation of it. You should then perform a HTTP redirect
-- to send the client to the IdP, appending the base64-encoded `AuthnRequest`
-- as a query parameter named @SAMLRequest@. You may wish to read the
-- [SAML2 specification for this process](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.2.SP-Initiated%20SSO:%20%20Redirect/POST%20Bindings|outline).
module Network.Wai.SAML2.Request (
    AuthnRequest(..),
    issueAuthnRequest,
    renderAuthnRequest
) where

-------------------------------------------------------------------------------

import Crypto.Random

import Data.Time.Clock
import Data.Time.Format

import Network.Wai.SAML2.XML

import Text.XML

import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

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

-- | Generates a base64-encoded `AuthnRequest` for SP initiated SSO, which
-- should be used as a query parameter named @SAMLRequest@.
renderAuthnRequest :: AuthnRequest -> B.ByteString
renderAuthnRequest AuthnRequest{..} =
    Base64.encode $
    BL.toStrict $
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
