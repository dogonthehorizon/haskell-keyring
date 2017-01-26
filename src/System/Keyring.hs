-- Copyright (c) 2014 Sebastian Wiesner <swiesner@lunaryorn.com>

-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:

-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.

{-# LANGUAGE CPP #-}

-- |Access to the keyring of the user.
--
-- This module provides access to the keyring of the current system.  Currently
-- this module supports the following keyrings:
--
-- * Keychain on OS X
--
-- * KWallet on KDE
--
-- The module automatically picks the best appropriate keyring.
module System.Keyring
       (
         -- * Data types
         Service(..)
       , Username(..)
       , Password(..)
         -- * Password storage
       , getPassword
       , setPassword
       , updatePassword
         -- * Exceptions
       , KeyringError(..)
       , KeyringMissingBackendError(..)
       ) where

import System.Keyring.Types

#ifdef DARWIN
import qualified System.Keyring.Darwin as Backend
#else
import qualified System.Keyring.Unix as Backend
#endif

-- |@'getPassword' service username@ gets the password for the given @username@
-- and @service@ from the keyring.
--
-- @service@ identifies the application which gets the password.
--
-- This function throws 'KeyringMissingBackendError' is no keyring
-- implementation exists for the current system and environment, and
-- 'KeyringError' if access to the keyring failed.
getPassword :: Service -> Username -> IO (Maybe Password)
getPassword = Backend.getPassword

-- |@'setPassword' service username password@ adds @password@ to the keyring.
--
-- @service@ identifies the application which sets the password.
--
-- This function throws 'KeyringMissingBackendError' is no keyring
-- implementation exists for the current system and environment, and
-- 'KeyringError' if access to the keyring failed.
setPassword :: Service -> Username -> Password -> IO ()
setPassword = Backend.setPassword

-- |@'updatePassword' service username password@ updates @password@ in the
-- default keyring.
--
-- @service@ identifies the application which updates the password.
--
-- This function throws 'KeyringMissingBackendError' is no keyring
-- implementation exists for the current system and environment, and
-- 'KeyringError' if access to the keyring failed.
updatePassword :: Service -> Username -> Password -> IO ()
updatePassword = Backend.updatePassword
