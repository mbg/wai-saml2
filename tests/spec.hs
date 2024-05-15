{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE TypeApplications #-}
import Test.Tasty
import qualified Parser
import qualified Validation

main :: IO ()
main = defaultMain $ testGroup "wai-saml2 tests"
    [ Parser.tests
    , Validation.tests
    ]
