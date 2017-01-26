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

{-# LANGUAGE ForeignFunctionInterface #-}

module System.Keyring.Darwin.Native where

import Data.Int (Int32, Int64)
import Data.Word (Word32)
import Foreign.C (CString)
import Foreign.Ptr (Ptr)

#include <Security/Security.h>

type UInt32 = #type UInt32
type CFTypeRef = Ptr ()
type CFStringRef = Ptr ()
type CFStringEncoding = #type CFStringEncoding
type CFIndex = #type CFIndex
type SecKeychainItemRef = Ptr ()
type SecKeychainRef = Ptr ()

-- |An internal OS X status code.
type OSStatus = #type OSStatus

#{enum OSStatus, ,
  errSecSuccess = errSecSuccess,
  errSecItemNotFound = errSecItemNotFound,
  errSecAuthFailed = errSecAuthFailed}

kCFStringEncodingUTF8 :: CFStringEncoding
kCFStringEncodingUTF8 = #const kCFStringEncodingUTF8

foreign import ccall unsafe "CoreFoundation/CoreFoundation.h CFRelease"
  c_CFRelease :: CFTypeRef -> IO ()

foreign import ccall unsafe "CoreFoundation/CoreFoundation.h CFStringGetMaximumSizeForEncoding"
  c_CFStringGetMaximumSizeForEncoding :: CFIndex -> CFStringEncoding -> CFIndex

foreign import ccall unsafe "CoreFoundation/CoreFoundation.h CFStringGetLength"
  c_CFStringGetLength :: CFStringRef -> CFIndex

foreign import ccall unsafe "CoreFoundation/CoreFoundation.h CFStringGetCString"
  c_CFStringGetCString :: CFStringRef -> CString -> CFIndex -> CFStringEncoding
                       -> IO Bool

foreign import ccall unsafe "Security/Security.h SecCopyErrorMessageString"
  c_SecCopyErrorMessageString :: OSStatus -> Ptr () -> IO CFStringRef

foreign import ccall unsafe "Security/Security.h SecKeychainItemFreeContent"
  c_SecKeychainItemFreeContent :: Ptr () -> CString -> IO OSStatus

foreign import ccall safe "Security/Security.h SecKeychainFindGenericPassword"
  c_SecKeychainFindGenericPassword :: CFTypeRef
                                   -> UInt32 -> CString
                                   -> UInt32 -> CString
                                   -> Ptr UInt32 -> Ptr CString
                                   -> Ptr SecKeychainItemRef
                                   -> IO OSStatus

foreign import ccall safe "Security/Security.h SecKeychainAddGenericPassword"
  c_SecKeychainAddGenericPassword :: SecKeychainRef
                                  -> UInt32 -> CString
                                  -> UInt32 -> CString
                                  -> UInt32 -> CString
                                  -> Ptr SecKeychainItemRef
                                  -> IO OSStatus

foreign import ccall safe "Security/Security.h SecKeychainItemModifyContent"
  c_SecKeychainItemModifyContent :: SecKeychainItemRef
                                 -> Ptr ()
                                 -> UInt32 -> CString
                                 -> IO OSStatus
