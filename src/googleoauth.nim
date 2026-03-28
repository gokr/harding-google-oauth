## ============================================================================
## Harding Google OAuth Library
## Provides Google OAuth2 authentication for Harding
## ============================================================================

import std/[strutils, tables, json, options]
import harding/core/types
import harding/interpreter/objects
import harding/interpreter/vm
import harding/packages/package_api

import ./googleoauth/googleoauth_impl
import ./googleoauth/googleuser_impl

const
  BootstrapHrd = staticRead("../lib/googleoauth/Bootstrap.hrd")
  GoogleOAuthHrd = staticRead("../lib/googleoauth/GoogleOAuth.hrd")
  GoogleUserHrd = staticRead("../lib/googleoauth/GoogleUser.hrd")

## ============================================================================
## Primitive Registration
## ============================================================================

proc registerGoogleOAuthPrimitives(interp: var Interpreter) =
  ## Register GoogleOAuth primitives

  let authCls = if interp.globals[].hasKey("GoogleOAuth"):
                  let val = interp.globals[]["GoogleOAuth"]
                  if val.kind == vkClass: val.classVal else: nil
                else:
                  nil

  if authCls == nil:
    warn("GoogleOAuth class not found")
    return

  debug("Found GoogleOAuth class, registering primitives")

  # Mark as Nim proxy
  authCls.isNimProxy = true
  authCls.hardingType = "GoogleOAuth"

  # Register new
  let newMethod = createCoreMethod("primitiveGoogleOAuthNew")
  newMethod.setNativeImpl(googleOAuthNewImpl)
  newMethod.hasInterpreterParam = true
  authCls.classMethods["primitiveGoogleOAuthNew"] = newMethod
  authCls.allClassMethods["primitiveGoogleOAuthNew"] = newMethod

  let publicNewMethod = createCoreMethod("new")
  publicNewMethod.setNativeImpl(googleOAuthNewImpl)
  publicNewMethod.hasInterpreterParam = true
  authCls.classMethods["new"] = publicNewMethod
  authCls.allClassMethods["new"] = publicNewMethod

  # Register getAuthorizationUrl:
  let authUrlMethod = createCoreMethod("primitiveGoogleOAuthGetAuthorizationUrl:")
  authUrlMethod.setNativeImpl(googleOAuthGetAuthorizationUrlImpl)
  authUrlMethod.hasInterpreterParam = true
  authCls.methods["primitiveGoogleOAuthGetAuthorizationUrl:"] = authUrlMethod
  authCls.allMethods["primitiveGoogleOAuthGetAuthorizationUrl:"] = authUrlMethod

  let publicAuthUrlMethod = createCoreMethod("getAuthorizationUrl:")
  publicAuthUrlMethod.setNativeImpl(googleOAuthGetAuthorizationUrlImpl)
  publicAuthUrlMethod.hasInterpreterParam = true
  authCls.methods["getAuthorizationUrl:"] = publicAuthUrlMethod
  authCls.allMethods["getAuthorizationUrl:"] = publicAuthUrlMethod

  # Register getAuthorizationUrl:usePKCE:
  let pkceMethod = createCoreMethod("primitiveGoogleOAuthGetAuthorizationUrl:usePKCE:")
  pkceMethod.setNativeImpl(googleOAuthGetAuthorizationUrlPKCEImpl)
  pkceMethod.hasInterpreterParam = true
  authCls.methods["primitiveGoogleOAuthGetAuthorizationUrl:usePKCE:"] = pkceMethod
  authCls.allMethods["primitiveGoogleOAuthGetAuthorizationUrl:usePKCE:"] = pkceMethod

  let publicPkceMethod = createCoreMethod("getAuthorizationUrl:usePKCE:")
  publicPkceMethod.setNativeImpl(googleOAuthGetAuthorizationUrlPKCEImpl)
  publicPkceMethod.hasInterpreterParam = true
  authCls.methods["getAuthorizationUrl:usePKCE:"] = publicPkceMethod
  authCls.allMethods["getAuthorizationUrl:usePKCE:"] = publicPkceMethod

  # Register exchangeCode:
  let exchangeMethod = createCoreMethod("primitiveGoogleOAuthExchangeCode:")
  exchangeMethod.setNativeImpl(googleOAuthExchangeCodeImpl)
  exchangeMethod.hasInterpreterParam = true
  authCls.methods["primitiveGoogleOAuthExchangeCode:"] = exchangeMethod
  authCls.allMethods["primitiveGoogleOAuthExchangeCode:"] = exchangeMethod

  let publicExchangeMethod = createCoreMethod("exchangeCode:")
  publicExchangeMethod.setNativeImpl(googleOAuthExchangeCodeImpl)
  publicExchangeMethod.hasInterpreterParam = true
  authCls.methods["exchangeCode:"] = publicExchangeMethod
  authCls.allMethods["exchangeCode:"] = publicExchangeMethod

  # Register verifyIdToken:
  let verifyMethod = createCoreMethod("primitiveGoogleOAuthVerifyIdToken:")
  verifyMethod.setNativeImpl(googleOAuthVerifyIdTokenImpl)
  verifyMethod.hasInterpreterParam = true
  authCls.methods["primitiveGoogleOAuthVerifyIdToken:"] = verifyMethod
  authCls.allMethods["primitiveGoogleOAuthVerifyIdToken:"] = verifyMethod

  let publicVerifyMethod = createCoreMethod("verifyIdToken:")
  publicVerifyMethod.setNativeImpl(googleOAuthVerifyIdTokenImpl)
  publicVerifyMethod.hasInterpreterParam = true
  authCls.methods["verifyIdToken:"] = publicVerifyMethod
  authCls.allMethods["verifyIdToken:"] = publicVerifyMethod

  # Register getUserInfo:
  let userInfoMethod = createCoreMethod("primitiveGoogleOAuthGetUserInfo:")
  userInfoMethod.setNativeImpl(googleOAuthGetUserInfoImpl)
  userInfoMethod.hasInterpreterParam = true
  authCls.methods["primitiveGoogleOAuthGetUserInfo:"] = userInfoMethod
  authCls.allMethods["primitiveGoogleOAuthGetUserInfo:"] = userInfoMethod

  let publicUserInfoMethod = createCoreMethod("getUserInfo:")
  publicUserInfoMethod.setNativeImpl(googleOAuthGetUserInfoImpl)
  publicUserInfoMethod.hasInterpreterParam = true
  authCls.methods["getUserInfo:"] = publicUserInfoMethod
  authCls.allMethods["getUserInfo:"] = publicUserInfoMethod

  # Register refreshAccessToken:
  let refreshMethod = createCoreMethod("primitiveGoogleOAuthRefreshAccessToken:")
  refreshMethod.setNativeImpl(googleOAuthRefreshAccessTokenImpl)
  refreshMethod.hasInterpreterParam = true
  authCls.methods["primitiveGoogleOAuthRefreshAccessToken:"] = refreshMethod
  authCls.allMethods["primitiveGoogleOAuthRefreshAccessToken:"] = refreshMethod

  let publicRefreshMethod = createCoreMethod("refreshAccessToken:")
  publicRefreshMethod.setNativeImpl(googleOAuthRefreshAccessTokenImpl)
  publicRefreshMethod.hasInterpreterParam = true
  authCls.methods["refreshAccessToken:"] = publicRefreshMethod
  authCls.allMethods["refreshAccessToken:"] = publicRefreshMethod

  debug("Registered GoogleOAuth primitives")
  
  authCls.methodsDirty = true
  authCls.version += 1
  invalidateSubclasses(authCls)

proc registerGoogleUserPrimitives(interp: var Interpreter) =
  ## Register GoogleUser primitives

  let userCls = if interp.globals[].hasKey("GoogleUser"):
                  let val = interp.globals[]["GoogleUser"]
                  if val.kind == vkClass: val.classVal else: nil
                else:
                  nil

  if userCls == nil:
    warn("GoogleUser class not found")
    return

  userCls.isNimProxy = true
  userCls.hardingType = "GoogleUser"

  # Register new
  let newMethod = createCoreMethod("primitiveGoogleUserNew")
  newMethod.setNativeImpl(googleUserNewImpl)
  newMethod.hasInterpreterParam = true
  userCls.classMethods["primitiveGoogleUserNew"] = newMethod
  userCls.allClassMethods["primitiveGoogleUserNew"] = newMethod

  let publicNewMethod = createCoreMethod("new")
  publicNewMethod.setNativeImpl(googleUserNewImpl)
  publicNewMethod.hasInterpreterParam = true
  userCls.classMethods["new"] = publicNewMethod
  userCls.allClassMethods["new"] = publicNewMethod

  debug("Registered GoogleUser primitives")
  
  userCls.methodsDirty = true
  userCls.version += 1
  invalidateSubclasses(userCls)

proc registerGoogleOAuthPrimitives(interp: var Interpreter) {.nimcall.} =
  ## Register all Google OAuth primitives with Harding
  registerGoogleOAuthPrimitives(interp)
  registerGoogleUserPrimitives(interp)

## ============================================================================
## Package Installation
## ============================================================================

proc installGoogleOAuth*(interp: var Interpreter) =
  ## Install the Google OAuth package into Harding

  let spec = HardingPackageSpec(
    name: "GoogleOAuth",
    version: "0.1.0",
    bootstrapPath: "lib/googleoauth/Bootstrap.hrd",
    sources: @[
      (path: "lib/googleoauth/Bootstrap.hrd", source: BootstrapHrd),
      (path: "lib/googleoauth/GoogleOAuth.hrd", source: GoogleOAuthHrd),
      (path: "lib/googleoauth/GoogleUser.hrd", source: GoogleUserHrd)
    ],
    registerPrimitives: registerGoogleOAuthPrimitives
  )

  discard installPackage(interp, spec)
  debug("Google OAuth package installed")
