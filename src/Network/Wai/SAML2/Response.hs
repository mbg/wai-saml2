--------------------------------------------------------------------------------
-- SAML2 Middleware for WAI                                                   --
--------------------------------------------------------------------------------
-- This source code is licensed under the MIT license found in the LICENSE    --
-- file in the root directory of this source tree.                            --
--------------------------------------------------------------------------------

-- | Types to reprsent SAML2 responses.
module Network.Wai.SAML2.Response (
    -- * SAML2 responses
    Response(..),
    removeSignature,
    extractSignedInfo,

    -- * Re-exports
    module Network.Wai.SAML2.StatusCode,
    module Network.Wai.SAML2.Signature
) where 

--------------------------------------------------------------------------------

import qualified Data.Text as T
import Data.Time

import Text.XML
import Text.XML.Cursor

import Network.Wai.SAML2.XML
import Network.Wai.SAML2.XML.Encrypted
import Network.Wai.SAML2.StatusCode
import Network.Wai.SAML2.Signature

--------------------------------------------------------------------------------

-- | Represents SAML2 responses.
data Response = Response {
    -- | The intended destination of this response.
    responseDestination :: !T.Text,
    -- | The unique ID of the response.
    responseId :: !T.Text,
    -- | The timestamp when the response was issued.
    responseIssueInstant :: !UTCTime,
    -- | The SAML version.
    responseVersion :: !T.Text,
    -- | The name of the issuer.
    responseIssuer :: !T.Text,
    -- | The status of the response.
    responseStatusCode :: !StatusCode,
    -- | The response signature.
    responseSignature :: !Signature,
    -- | The (encrypted) assertion.
    responseEncryptedAssertion :: !EncryptedAssertion
} deriving (Eq, Show)

instance FromXML Response where 
    parseXML cursor = do
        issueInstant <- parseUTCTime 
                      $ T.concat 
                      $ attribute "IssueInstant" cursor

        statusCode <- case parseXML cursor of
            Nothing -> fail "Invalid status code"
            Just sc -> pure sc

        encAssertion <- oneOrFail "EncryptedAssertion is required" 
                    (   cursor
                    $/  element (saml2Name "EncryptedAssertion")
                    &/  element (xencName "EncryptedData")
                    ) >>= parseXML

        signature <- oneOrFail "Signature is required" (
            cursor $/ element (dsName "Signature") ) >>= parseXML

        pure Response{
            responseDestination = T.concat $ attribute "Destination" cursor,
            responseId = T.concat $ attribute "ID" cursor,
            responseIssueInstant = issueInstant,
            responseVersion = T.concat $ attribute "Version" cursor,
            responseIssuer = T.concat $ 
                cursor $/ element (saml2Name "Issuer") &/ content,
            responseStatusCode = statusCode,
            responseSignature = signature,
            responseEncryptedAssertion = encAssertion
        }
    
--------------------------------------------------------------------------------

-- | Returns 'True' if the argument is not a @<Signature>@ element.
isNotSignature :: Node -> Bool 
isNotSignature (NodeElement e) = elementName e /= dsName "Signature" 
isNotSignature _ = True

-- | 'removeSignature' @document@ removes all @<Signature>@ elements from
-- @document@ and returns the resulting document.
removeSignature :: Document -> Document
removeSignature (Document prologue root misc) = 
    let Element n attr ns = root
    in Document prologue (Element n attr (filter isNotSignature ns)) misc
          
-- | Returns all nodes at @cursor@.
nodes :: MonadFail m => Cursor -> m Node
nodes = pure . node 

-- | 'extractSignedInfo' @cursor@ extracts the SignedInfo element from the 
-- document reprsented by @cursor@.
extractSignedInfo :: MonadFail m => Cursor -> m Element
extractSignedInfo cursor = do 
    NodeElement signedInfo <- oneOrFail "SignedInfo is required" 
                            ( cursor
                           $/ element (dsName "Signature") 
                           &/ element (dsName "SignedInfo") 
                          ) >>= nodes
    pure signedInfo

--------------------------------------------------------------------------------
