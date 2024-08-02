module Validation where

import Control.Monad.Trans.Except
import Crypto.PubKey.RSA (PublicKey)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as Base64
import Data.Time.Format.ISO8601
import qualified Data.X509 as X509
import qualified Data.X509.Memory as X509
import Network.Wai.SAML2
import Network.Wai.SAML2.Validation
import System.FilePath
import Test.Tasty
import Test.Tasty.HUnit

-- | Get a public key from a X.509 certificate
parseCertificate :: B.ByteString -> PublicKey
parseCertificate certificate = case X509.readSignedObjectFromMemory certificate of
    [signedCert] -> case X509.certPubKey $ X509.signedObject $ X509.getSigned signedCert of
        X509.PubKeyRSA key -> key
        other -> error $ "Expected PubKeyRSA, but got " <> show other
    xs -> error $ show xs

run :: FilePath -> String -> FilePath -> IO ()
run certPath timestamp respPath = do
    cert <- B.readFile $ prefix </> certPath
    xml <- B.readFile $ prefix </> respPath
    now <- iso8601ParseM timestamp

    let pub = parseCertificate cert
        cfg = saml2ConfigNoEncryption pub

    assertion <- runExceptT $ do
        (responseXmlDoc, samlResponse) <- decodeResponse $ Base64.encode xml
        validateSAMLResponse cfg responseXmlDoc samlResponse now

    case assertion of
        Left err -> assertFailure $ show err
        Right _ -> pure ()

prefix :: FilePath
prefix = "tests/data"

tests :: TestTree
tests = testGroup "Validate SAML2 Response"
    [ testCase "AzureAD signed response"
        $ run "azuread.crt" "2023-05-10T01:20:00Z" "azuread-signed-response.xml"
    , testCase "AzureAD signed assertion"
        $ run "azuread.crt" "2023-05-09T16:00:00Z" "azuread-signed-assertion.xml"
    , testCase "Okta with AttributeStatement"
        $ run "okta.crt" "2023-06-16T06:43:00.000Z" "okta-attributes.xml"
    ]
