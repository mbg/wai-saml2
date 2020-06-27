--------------------------------------------------------------------------------
-- SAML2 Middleware for WAI                                                   --
--------------------------------------------------------------------------------
-- This source code is licensed under the MIT license found in the LICENSE    --
-- file in the root directory of this source tree.                            --
--------------------------------------------------------------------------------

-- | SAML2 status codes.
module Network.Wai.SAML2.StatusCode (
    StatusCode(..)
) where 

--------------------------------------------------------------------------------

import Control.Monad

import qualified Data.Text as T

import Text.XML.Cursor

import Network.Wai.SAML2.XML

--------------------------------------------------------------------------------

-- | Enumerates SAML2 status codes.
data StatusCode
    -- | The response indicates success!  
    = Success
    deriving (Eq, Show)

instance FromXML StatusCode where 
    parseXML cursor =  
        let value = T.concat 
                $   cursor 
                $/  element (saml2pName "Status")
                &/  element (saml2pName "StatusCode") 
                >=> attribute "Value"
        in case value of
            "urn:oasis:names:tc:SAML:2.0:status:Success" -> pure Success
            _ -> fail "Not a valid status code."
    

--------------------------------------------------------------------------------
