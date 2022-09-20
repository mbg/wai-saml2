module Network.Wai.SAML2.Request
    ( AuthnRequest(..)
    , issueAuthnRequest
    , renderAuthnRequest
    ) where

import Crypto.Random
import Data.Time.Clock
import Data.Time.Format
import Network.Wai.SAML2.XML
import Text.XML
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

-- | Parameters for SP-initiated SSO
data AuthnRequest = AuthnRequest
    { authnRequestTimestamp :: UTCTime
    -- ^ the time at which 'AuthnRequest' is created
    , authnRequestID :: T.Text
    -- ^ Unique identifier for 'AuthnRequest' which should be preserved in the response
    , authnRequestIssuer :: T.Text
    -- ^ SP Entity ID
    , authnRequestAllowCreate :: Bool
    -- ^ Allow IdP to generate a new identifier
    , authnRequestNameIDFormat :: T.Text
    }

-- | Create a default 'AuthnRequest' with the current timestamp and randomly-generated ID.
issueAuthnRequest
    :: T.Text -- ^ SP Entity ID
    -> IO AuthnRequest
issueAuthnRequest authnRequestIssuer = do
    authnRequestTimestamp <- getCurrentTime
    authnRequestID <- T.decodeUtf8 . Base64.encode <$> getRandomBytes 16
    pure AuthnRequest
        { authnRequestAllowCreate = True
        , authnRequestNameIDFormat
            = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
        , ..
        }

-- | Generate a base64-encoded AuthnRequest for SP initiated SSO, which should be used as a SAMLRequest parameter.
-- See also: http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.2.SP-Initiated%20SSO:%20%20Redirect/POST%20Bindings|outline
renderAuthnRequest :: AuthnRequest -> B.ByteString
renderAuthnRequest AuthnRequest{..} = Base64.encode
    $ BL.toStrict
    $ renderLBS def
    $ Document
        { documentPrologue = Prologue [] Nothing []
        , documentRoot = root
        , documentEpilogue = []
        }
    where
        timestamp = T.pack
            $ formatTime defaultTimeLocale timeFormat authnRequestTimestamp
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
