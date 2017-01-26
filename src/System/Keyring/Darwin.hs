-- Copyright (c) 2014 Sebastian Wiesner <swiesner@lunaryorn.com>
-- Copyright (c) 2017 Fernando Freire <dogonthehorizon@gmail.com>

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

{-# LANGUAGE DeriveDataTypeable #-}

-- |Access to the OS X Keychain.
--
-- This module is only available on OS X.  See "System.Keyring.Unix" for keyring
-- support on other Unix systems.
module System.Keyring.Darwin
       (
         -- * Keychain access
         setPassword
       , getPassword
       , updatePassword
         -- * Error handling
       , KeychainError(..)
       , OSStatus
       ) where

import System.Keyring.Types
import System.Keyring.Darwin.Native

import qualified Data.ByteString.UTF8 as UTF8

import Control.Exception (Exception(..),bracket,throwIO)
import Control.Monad (when,unless,void)
import Data.ByteString (ByteString,useAsCStringLen,packCString,packCStringLen)
import Data.Typeable (Typeable,cast)
import Foreign.C (CString)
import Foreign.Ptr (Ptr,nullPtr)
import Foreign.Storable (peek)
import Foreign.Marshal.Alloc (alloca,allocaBytes)
import Text.Printf (printf)

data KeychainError =
  -- |@'KeychainError' message status@ denotes an error which occurred when
  -- accessing Keychain.
  --
  -- @message@ is the human-readable error message reported by the system, and
  -- @status@ is the internal status code.
  --
  -- See <https://developer.apple.com/library/mac/documentation/security/Reference/keychainservices/Reference/reference.html#//apple_ref/doc/uid/TP30000898-CH5g-CJBEABHG Keychain Services Result Codes>
  -- for a list of all status codes.
  --
  -- Note that this error is /not/ thrown for the status codes
  -- @errSecItemNotFound@ and @errSecAuthFailed@.  For these status codes,
  -- 'getPassword' simply returns 'Nothing'.
  KeychainError (Maybe String) OSStatus deriving Typeable

instance Show KeychainError where
  show (KeychainError Nothing status) =
    printf "Keychain access failed: status %s" status
  show (KeychainError (Just msg) status) =
    printf "Keychain access failed: %s (status %d)" msg status

instance Exception KeychainError where
  toException = toException . KeyringError
  fromException x = do
    KeyringError e <- fromException x
    cast e

throwKeychainError :: OSStatus -> IO a
throwKeychainError status = do
  messageResult <- secKeychainCopyErrorMessageString status
  let message = fmap UTF8.toString messageResult
  throwIO (KeychainError message status)

secKeychainCopyErrorMessageString :: OSStatus -> IO (Maybe ByteString)
secKeychainCopyErrorMessageString status =
  bracket
  (c_SecCopyErrorMessageString status nullPtr)
  (\s -> when (s /= nullPtr) (c_CFRelease s))
  convertCFString
  where
    convertCFString s | s == nullPtr = return Nothing
    convertCFString s = do
      let encoding = kCFStringEncodingUTF8
      let bufferSize = c_CFStringGetMaximumSizeForEncoding (c_CFStringGetLength s) encoding
      allocaBytes (fromIntegral bufferSize) (getCString s encoding bufferSize)
    getCString s encoding bufferSize buffer = do
      result <- c_CFStringGetCString s buffer bufferSize encoding
      if result
        then fmap Just (packCString buffer)
        else return Nothing

secKeychainFindGenericPassword :: ByteString -> ByteString -> IO (Maybe ByteString)
secKeychainFindGenericPassword service username =
  useAsCStringLen service $ \(serviceB, serviceL) ->
    useAsCStringLen username $ \(userB, userL) ->
      alloca $ \passLenBuffer ->
        alloca $ \passBuffer -> do
          result <- c_SecKeychainFindGenericPassword
                    nullPtr -- Default keychain
                    (fromIntegral serviceL) serviceB
                    (fromIntegral userL) userB
                    passLenBuffer passBuffer
                    nullPtr -- Ignore the item ref

          bracket (peek passBuffer)
            (\password -> when (password /= nullPtr)
                          (void $ c_SecKeychainItemFreeContent nullPtr password))
            (handleResult result passLenBuffer)
  where
    handleResult :: OSStatus -> Ptr UInt32 -> CString -> IO (Maybe ByteString)
    handleResult result password_l_buf password_b = case result of
      _ | result == errSecSuccess -> do
        password_l <- peek password_l_buf
        fmap Just (packCStringLen (password_b, fromIntegral password_l))
      _ | result == errSecItemNotFound ||
          result == errSecAuthFailed -> return Nothing
      _ -> throwKeychainError result

secKeychainFindGenericPasswordRef :: ByteString -> ByteString -> IO SecKeychainItemRef
secKeychainFindGenericPasswordRef service username =
  useAsCStringLen service $ \(serviceB, serviceL) ->
    useAsCStringLen username $ \(userB, userL) ->
      alloca $ \refBuff -> do
          result <- c_SecKeychainFindGenericPassword
                    nullPtr -- Default keychain
                    (fromIntegral serviceL) serviceB
                    (fromIntegral userL) userB
                    nullPtr nullPtr
                    refBuff -- Ignore the item ref

          if result /= errSecSuccess
             then throwKeychainError result
             else peek refBuff

secKeychainItemModifyContent :: ByteString -> ByteString -> ByteString -> IO ()
secKeychainItemModifyContent service username password = do
  keychainRef <- secKeychainFindGenericPasswordRef service username
  useAsCStringLen password $ \(passB, passL) -> do
    result <- c_SecKeychainItemModifyContent
              keychainRef
              nullPtr -- No attributes to update; just the password
              (fromIntegral passL) passB

    unless (result == errSecSuccess) (throwKeychainError result)


secKeychainAddGenericPassword :: ByteString -> ByteString -> ByteString -> IO ()
secKeychainAddGenericPassword service username password =
  useAsCStringLen service $ \(serviceB, serviceL) ->
    useAsCStringLen username $ \(userB, userL) ->
      useAsCStringLen password $ \(passB, passL) -> do
        result <- c_SecKeychainAddGenericPassword
                  nullPtr -- Default Keychain
                  (fromIntegral serviceL) serviceB
                  (fromIntegral userL) userB
                  (fromIntegral passL) passB
                  nullPtr -- Ignore the returned item

        unless (result == errSecSuccess) (throwKeychainError result)

-- |@'setPassword' service username password@ adds @password@ for @username@
-- to the user's keychain.
--
-- @username@ is the name of the user whose password to set.  @service@
-- identifies the application which sets the password.
--
-- This function throws 'KeychainError' if access to the Keychain failed.
setPassword :: Service -> Username -> Password -> IO ()
setPassword (Service service) (Username username) (Password password) =
  secKeychainAddGenericPassword service_bytes username_bytes password_bytes
  where service_bytes = UTF8.fromString service
        username_bytes = UTF8.fromString username
        password_bytes = UTF8.fromString password

updatePassword :: Service -> Username -> Password -> IO ()
updatePassword (Service service) (Username username) (Password password) =
  secKeychainItemModifyContent service_bytes username_bytes password_bytes
  where service_bytes = UTF8.fromString service
        username_bytes = UTF8.fromString username
        password_bytes = UTF8.fromString password

-- |@'getPassword' service username@ gets password for a given @username@ and
-- @service@.  If the password was not found, return 'Nothing' instead.
--
-- This function throws 'KeychainError' if access to the Keychain failed.
getPassword :: Service -> Username -> IO (Maybe Password)
getPassword (Service service) (Username username) = do
  password_bytes <- secKeychainFindGenericPassword service_bytes username_bytes
  return (fmap (Password . UTF8.toString) password_bytes)
  where service_bytes = UTF8.fromString service
        username_bytes = UTF8.fromString username
