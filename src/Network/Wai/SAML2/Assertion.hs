--------------------------------------------------------------------------------
-- SAML2 Middleware for WAI                                                   --
--------------------------------------------------------------------------------
-- This source code is licensed under the MIT license found in the LICENSE    --
-- file in the root directory of this source tree.                            --
--------------------------------------------------------------------------------

-- | Types to represent SAML2 assertions and functions to parse them from XML.
module Network.Wai.SAML2.Assertion (
    SubjectConfirmationMethod(..),
    SubjectConfirmation(..),
    Subject(..),
    Conditions(..),
    AuthnStatement(..),
    AssertionAttribute(..),
    AttributeStatement,
    parseAttributeStatement,
    Assertion(..)
) where

--------------------------------------------------------------------------------

import Control.Monad

import qualified Data.Text as T
import Data.Time

import Text.XML.Cursor

import Network.Wai.SAML2.XML

--------------------------------------------------------------------------------

-- | Enumerates different subject confirmation methods.
-- See http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#4.2.1.Subject%20Confirmation%20|outline
data SubjectConfirmationMethod
    = HolderOfKey -- ^ urn:oasis:names:tc:SAML:2.0:cm:holder-of-key
    | SenderVouches -- ^ urn:oasis:names:tc:SAML:2.0:cm:sender-vouches
    | Bearer -- ^ urn:oasis:names:tc:SAML:2.0:cm:bearer
    deriving (Eq, Show)

instance FromXML SubjectConfirmationMethod where 
    parseXML cursor = case T.concat $ attribute "Method" cursor of 
        "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" -> pure HolderOfKey
        "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches" -> pure SenderVouches
        "urn:oasis:names:tc:SAML:2.0:cm:bearer" -> pure Bearer
        _ -> fail "Not a valid SubjectConfirmationMethod."

--------------------------------------------------------------------------------

-- | Represents a subject confirmation record.
data SubjectConfirmation = SubjectConfirmation {
    -- | The subject confirmation method used.
    subjectConfirmationMethod :: !SubjectConfirmationMethod,
    -- | The address of the subject.
    subjectConfirmationAddress :: !T.Text,
    -- | A timestamp.
    subjectConfirmationNotOnOrAfter :: !UTCTime,
    -- | The recipient.
    subjectConfirmationRecipient :: !T.Text
} deriving (Eq, Show)

instance FromXML SubjectConfirmation where 
    parseXML cursor = do 
        method <- parseXML cursor

        notOnOrAfter <- parseUTCTime $ T.concat $
            cursor $/ element (saml2Name "SubjectConfirmationData") 
                  >=> attribute "NotOnOrAfter"

        pure SubjectConfirmation{
            subjectConfirmationMethod = method,
            subjectConfirmationAddress = T.concat $
                cursor $/ element (saml2Name "SubjectConfirmationData")
                      >=> attribute "Address",
            subjectConfirmationNotOnOrAfter = notOnOrAfter,
            subjectConfirmationRecipient = T.concat $
                cursor $/ element (saml2Name "SubjectConfirmationData")
                      >=> attribute "Recipient"
        }


-- | The "NameID" of subject.
data SubjectNameID = SubjectNameID {
    nameIdValue :: !T.Text
} deriving (Eq, Show)

instance FromXML SubjectNameID where 
    parseXML cursor = do 
        pure SubjectNameID {
            nameIdValue = T.concat $ cursor $/ content
        }

-- | The subject of the assertion.
data Subject = Subject {
    -- | The list of subject confirmation elements, if any.
    subjectConfirmations :: ![SubjectConfirmation],
    subjectNameId :: !SubjectNameID
} deriving (Eq, Show)

instance FromXML Subject where 
    parseXML cursor = do 
        confirmations <- sequence $ 
            cursor $/ element (saml2Name "SubjectConfirmation") &| parseXML
        nameId <- oneOrFail "SubjectNameID is required" $ 
            cursor $/ element (saml2Name "NameID") >=> parseXML

        pure Subject{
            subjectConfirmations = confirmations,
            subjectNameId        = nameId
        }

--------------------------------------------------------------------------------

-- | Conditions under which a SAML assertion is issued.
data Conditions = Conditions {
    -- | The time when the assertion is valid from (inclusive).
    conditionsNotBefore :: !UTCTime,
    -- | The time the assertion is valid to (not inclusive).
    conditionsNotOnOrAfter :: !UTCTime,
    -- | The intended audience of the assertion.
    conditionsAudience :: !T.Text
} deriving (Eq, Show)

instance FromXML Conditions where
    parseXML cursor = do 
        notBefore <- parseUTCTime $ 
            T.concat $ attribute "NotBefore" cursor
        notOnOrAfter <- parseUTCTime $ 
            T.concat $ attribute "NotOnOrAfter" cursor

        pure Conditions{
            conditionsNotBefore = notBefore,
            conditionsNotOnOrAfter = notOnOrAfter,
            conditionsAudience = T.concat $ 
                cursor $/ element (saml2Name "AudienceRestriction")
                    &/ element (saml2Name "Audience")
                    &/ content
        }

--------------------------------------------------------------------------------

-- | SAML2 authentication statements.
data AuthnStatement = AuthnStatement {
    -- | The timestamp when the assertion was issued.
    authnStatementInstant :: !UTCTime,
    -- | The session index.
    authnStatementSessionIndex :: !T.Text,
    -- | The statement locality.
    authnStatementLocality :: !T.Text
} deriving (Eq, Show)

instance FromXML AuthnStatement where
    parseXML cursor = do 
        issueInstant <- parseUTCTime $ 
            T.concat $ attribute "AuthnInstant" cursor

        pure AuthnStatement{
            authnStatementInstant = issueInstant,
            authnStatementSessionIndex = T.concat $ 
                attribute "SessionIndex" cursor, 
            authnStatementLocality = T.concat $ 
                cursor $/ element (saml2Name "SubjectLocality") 
                    >=> attribute "Address"
        }

--------------------------------------------------------------------------------

-- | SAML2 assertion attributes.
data AssertionAttribute = AssertionAttribute {
    -- | The name of the attribute.
    attributeName :: !T.Text,
    -- | A friendly attribute name, if it exists.
    attributeFriendlyName :: !(Maybe T.Text),
    -- | The name format.
    attributeNameFormat :: !T.Text,
    -- | The value of the attribute.
    attributeValue :: !T.Text
} deriving (Eq, Show)

instance FromXML AssertionAttribute where
    parseXML cursor = do  
        pure AssertionAttribute{
            attributeName = T.concat $ attribute "Name" cursor,
            attributeFriendlyName = 
                toMaybeText $ attribute "FriendlyName" cursor,
            attributeNameFormat = T.concat $ attribute "NameFormat" cursor,
            attributeValue = T.concat $ 
                cursor $/ element (saml2Name "AttributeValue") &/ content
        }

-- | SAML2 assertion statements (collections of assertion attributes).
type AttributeStatement = [AssertionAttribute]

-- | 'parseAttributeStatement' @cursor@ parses an 'AttributeStatement'.
parseAttributeStatement :: Cursor -> AttributeStatement
parseAttributeStatement cursor = 
    cursor $/ element (saml2Name "Attribute") >=> parseXML

--------------------------------------------------------------------------------

-- | Represents a SAML2 assertion.
data Assertion = Assertion {
    -- | The unique ID of this assertion. It is important to keep track of
    -- these in order to avoid replay attacks. 
    assertionId :: !T.Text,
    -- | The date and time when the assertion was issued.
    assertionIssued :: !UTCTime,
    -- | The name of the entity that issued this assertion.
    assertionIssuer :: !T.Text,
    -- | The subject of the assertion.
    assertionSubject :: !Subject,
    -- | The conditions under which the assertion is issued.
    assertionConditions :: !Conditions,
    -- | The authentication statement included in the assertion.
    assertionAuthnStatement :: !AuthnStatement,
    -- | The assertion's attribute statement.
    assertionAttributeStatement :: !AttributeStatement
} deriving (Eq, Show)

instance FromXML Assertion where 
    parseXML cursor = do 
        issueInstant <- parseUTCTime $  
            T.concat $ attribute "IssueInstant" cursor

        subject <- oneOrFail "Subject is required" $
            cursor $/ element (saml2Name "Subject") >=> parseXML

        conditions <- oneOrFail "Conditions are required" $
            cursor $/ element (saml2Name "Conditions") >=> parseXML

        authnStatement <- oneOrFail "AuthnStatement is required" $ 
            cursor $/ element (saml2Name "AuthnStatement") >=> parseXML

        pure Assertion{
            assertionId = T.concat $ attribute "ID" cursor,
            assertionIssued = issueInstant,
            assertionIssuer = T.concat $ 
                cursor $/ element (saml2Name "Issuer") &/ content,
            assertionSubject = subject,
            assertionConditions = conditions,
            assertionAuthnStatement = authnStatement,
            assertionAttributeStatement = 
                cursor $/ element (saml2Name "AttributeStatement") 
                    >=> parseAttributeStatement 
        }

--------------------------------------------------------------------------------
