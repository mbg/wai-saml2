{-# LANGUAGE LambdaCase #-}
import Crypto.PubKey.RSA (PublicKey)
import Network.Wai.SAML2
import Network.Wai.SAML2.C14N
import Network.Wai.SAML2.Validation
import RIO
import System.Environment
import qualified Data.ByteString.Base64 as BS
import qualified Data.ByteString.Char8 as BS
import qualified Data.X509 as X509
import qualified Data.X509.Memory as X509

parseCertificate :: ByteString -> PublicKey
parseCertificate certificate = case X509.readSignedObjectFromMemory certificate of
    [signedCert] -> case X509.certPubKey $ X509.signedObject $ X509.getSigned signedCert of
        X509.PubKeyRSA key -> key
        other -> error $ "Expected PubKeyRSA, but got " <> show other
    xs -> error $ show xs

main :: IO ()
main = getArgs >>= \case
    [certPath, path] -> do
        cert <- readFileBinary certPath
        let pub = parseCertificate cert
            cfg = saml2ConfigNoEncryption pub
        bs <- BS.init <$> readFileBinary path

        -- c14nを適用したXMLを出力
        canonicalise (either error id $ BS.decode bs) >>= BS.putStrLn

        result <- validateResponse cfg bs
        print result
    _ -> fail "cabal run validate okta.crt okta.b64"
