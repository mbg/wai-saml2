import Network.Wai.SAML2.Response
import Network.Wai.SAML2.XML
import System.FilePath
import Test.Tasty
import Test.Tasty.Golden
import Text.Show.Pretty
import Text.XML.Cursor
import qualified Data.ByteString.Lazy.Char8 as BC
import qualified Text.XML as XML

run :: FilePath -> IO BC.ByteString
run src = do
    doc <- XML.readFile XML.def src
    resp <- parseXML (fromDocument doc)
    pure $ BC.pack $ ppShow (resp :: Response)

main :: IO ()
main = defaultMain $ testGroup "Parse SAML2 response"
    [ mkGolden $ prefix </> "keycloak.xml"
    , mkGolden $ prefix </> "okta.xml"
    , mkGolden $ prefix </> "google.xml"
    ]
    where
        prefix = "tests/data"
        mkGolden path = goldenVsStringDiff
                (takeBaseName path)
                (\ref new -> ["diff", "-u", ref, new])
                (path <.> "expected")
                (run path)
