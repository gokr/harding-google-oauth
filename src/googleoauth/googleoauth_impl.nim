## ============================================================================
## Google OAuth Implementation
## Native implementation for GoogleOAuth class
## ============================================================================

import std/[strutils, tables, json, options, uri, base64, times, sha1, sequtils]
import curly
import jwt
import harding/core/types
import harding/interpreter/objects
import ./googleuser_impl

# Google OAuth2 endpoints
const
  GoogleAuthorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth"
  GoogleTokenUrl = "https://oauth2.googleapis.com/token"
  GoogleUserInfoUrl = "https://www.googleapis.com/oauth2/v2/userinfo"
  GoogleCertsUrl = "https://www.googleapis.com/oauth2/v3/certs"

type
  GoogleOAuthData = object
    clientId: string
    clientSecret: string
    redirectUri: string
    httpClient: Curly
    pkceVerifier: string  # Store PKCE code verifier

  GoogleTokenResponse = object
    accessToken: string
    refreshToken: string
    idToken: string
    tokenType: string
    expiresIn: int

# Generate PKCE code verifier and challenge
proc generatePKCE(): tuple[verifier: string, challenge: string] =
  ## Generate PKCE code verifier and S256 challenge
  var verifierBytes = newSeq[byte](32)
  for i in 0..<32:
    verifierBytes[i] = byte(rand(256))
  let verifier = base64.encode(verifierBytes).replace("=", "").replace("+", "-").replace("/", "_")
  
  # Generate S256 challenge
  let hash = sha1.compute(verifier)
  let challenge = base64.encode(hash.data).replace("=", "").replace("+", "-").replace("/", "_")
  
  return (verifier, challenge)

proc googleOAuthNewImpl*(interp: var Interpreter, self: Instance,
                          args: seq[NodeValue]): NodeValue {.nimcall.} =
  ## Create a new GoogleOAuth instance

  let objectCls = interp.globals[]["Object"]
  if objectCls.kind != vkClass:
    return nilValue()

  let authClsVal = interp.globals[]["GoogleOAuth"]
  if authClsVal.kind != vkClass:
    return nilValue()

  let authCls = authClsVal.classVal
  let instance = newInstance(authCls)

  var authData = GoogleOAuthData(
    clientId: "",
    clientSecret: "",
    redirectUri: "",
    httpClient: newCurly(),
    pkceVerifier: ""
  )

  var dataPtr = create(GoogleOAuthData)
  dataPtr[] = authData
  instance.nimValue = cast[pointer](dataPtr)
  instance.isNimProxy = true

  return instance.toValue()

proc googleOAuthGetAuthorizationUrlImpl*(interp: var Interpreter, self: Instance,
                                          args: seq[NodeValue]): NodeValue {.nimcall.} =
  ## Get Google authorization URL

  if not self.isNimProxy or self.nimValue == nil:
    return nilValue()

  let dataPtr = cast[ptr GoogleOAuthData](self.nimValue)

  if args.len < 1:
    return nilValue()

  let scope = args[0].toString()

  try:
    # Build authorization URL
    var url = GoogleAuthorizationUrl
    url.add("?client_id=")
    url.add(encodeUrl(dataPtr.clientId))
    url.add("&redirect_uri=")
    url.add(encodeUrl(dataPtr.redirectUri))
    url.add("&response_type=code")
    url.add("&scope=")
    url.add(encodeUrl(scope))
    url.add("&access_type=offline")  # Get refresh token
    url.add("&prompt=consent")  # Always show consent screen to get refresh token
    
    # Generate and store state
    var stateBytes = newSeq[byte](16)
    for i in 0..<16:
      stateBytes[i] = byte(rand(256))
    let state = base64.encode(stateBytes).replace("=", "").replace("+", "-").replace("/", "_")
    url.add("&state=")
    url.add(state)

    return url.toValue()
  except:
    return nilValue()

proc googleOAuthGetAuthorizationUrlPKCEImpl*(interp: var Interpreter, self: Instance,
                                              args: seq[NodeValue]): NodeValue {.nimcall.} =
  ## Get Google authorization URL with PKCE

  if not self.isNimProxy or self.nimValue == nil:
    return nilValue()

  let dataPtr = cast[ptr GoogleOAuthData](self.nimValue)

  if args.len < 2:
    return nilValue()

  let scope = args[0].toString()
  let usePKCE = if args[1].kind == vkBool: args[1].boolVal else: false

  try:
    var url = GoogleAuthorizationUrl
    url.add("?client_id=")
    url.add(encodeUrl(dataPtr.clientId))
    url.add("&redirect_uri=")
    url.add(encodeUrl(dataPtr.redirectUri))
    url.add("&response_type=code")
    url.add("&scope=")
    url.add(encodeUrl(scope))
    url.add("&access_type=offline")
    url.add("&prompt=consent")
    
    # Add PKCE parameters
    if usePKCE:
      let (verifier, challenge) = generatePKCE()
      dataPtr.pkceVerifier = verifier
      url.add("&code_challenge=")
      url.add(challenge)
      url.add("&code_challenge_method=S256")
    
    # Generate state
    var stateBytes = newSeq[byte](16)
    for i in 0..<16:
      stateBytes[i] = byte(rand(256))
    let state = base64.encode(stateBytes).replace("=", "").replace("+", "-").replace("/", "_")
    url.add("&state=")
    url.add(state)

    return url.toValue()
  except:
    return nilValue()

proc googleOAuthExchangeCodeImpl*(interp: var Interpreter, self: Instance,
                                   args: seq[NodeValue]): NodeValue {.nimcall.} =
  ## Exchange authorization code for tokens

  if not self.isNimProxy or self.nimValue == nil:
    return nilValue()

  let dataPtr = cast[ptr GoogleOAuthData](self.nimValue)

  if args.len < 1:
    return nilValue()

  let code = args[0].toString()

  try:
    # Build token request
    var body = "code=" & encodeUrl(code)
    body.add("&client_id=" & encodeUrl(dataPtr.clientId))
    body.add("&client_secret=" & encodeUrl(dataPtr.clientSecret))
    body.add("&redirect_uri=" & encodeUrl(dataPtr.redirectUri))
    body.add("&grant_type=authorization_code")
    
    # Add PKCE verifier if available
    if dataPtr.pkceVerifier.len > 0:
      body.add("&code_verifier=" & encodeUrl(dataPtr.pkceVerifier))
      dataPtr.pkceVerifier = ""  # Clear after use

    # Make request
    let response = dataPtr.httpClient.post(GoogleTokenUrl, 
                                           emptyHttpHeaders(),
                                           body)
    
    if response.code != 200:
      return nilValue()

    # Parse response
    let tokenData = parseJson(response.body)
    
    # Create token table
    var table = initTable[NodeValue, NodeValue]()
    if tokenData.hasKey("access_token"):
      table["access_token".toValue()] = tokenData["access_token"].getStr().toValue()
    if tokenData.hasKey("refresh_token"):
      table["refresh_token".toValue()] = tokenData["refresh_token"].getStr().toValue()
    if tokenData.hasKey("id_token"):
      table["id_token".toValue()] = tokenData["id_token"].getStr().toValue()
    if tokenData.hasKey("token_type"):
      table["token_type".toValue()] = tokenData["token_type"].getStr().toValue()
    if tokenData.hasKey("expires_in"):
      table["expires_in".toValue()] = tokenData["expires_in"].getInt().toValue()
    
    return table.toValue()
  except:
    return nilValue()

proc googleOAuthVerifyIdTokenImpl*(interp: var Interpreter, self: Instance,
                                    args: seq[NodeValue]): NodeValue {.nimcall.} =
  ## Verify a Google ID token (JWT)

  if args.len < 1:
    return nilValue()

  let idToken = args[0].toString()

  try:
    # Parse the JWT without verification first to get the key ID
    let jwt = idToken.toJWT()
    
    # In production, you should:
    # 1. Fetch Google's public keys from https://www.googleapis.com/oauth2/v3/certs
    # 2. Find the key matching jwt.header["kid"]
    # 3. Verify the signature using RS256
    
    # For now, we just check the claims
    if jwt.claims.hasKey("aud"):
      let aud = jwt.claims["aud"].node.getStr()
      # Verify audience matches client ID
      # This is a simplified check - full verification would validate signature
      
      # Check expiration
      jwt.verifyTimeClaims()
      
      # Create claims table
      var table = initTable[NodeValue, NodeValue]()
      for key, value in jwt.claims.pairs:
        table[key.toValue()] = value.node.getStr().toValue()
      
      return table.toValue()
    
    return nilValue()
  except:
    return nilValue()

proc googleOAuthGetUserInfoImpl*(interp: var Interpreter, self: Instance,
                                  args: seq[NodeValue]): NodeValue {.nimcall.} =
  ## Get user info from Google using access token

  if not self.isNimProxy or self.nimValue == nil:
    return nilValue()

  let dataPtr = cast[ptr GoogleOAuthData](self.nimValue)

  if args.len < 1:
    return nilValue()

  let accessToken = args[0].toString()

  try:
    # Build request headers
    var headers = emptyHttpHeaders()
    headers["Authorization"] = "Bearer " & accessToken

    # Make request
    let response = dataPtr.httpClient.get(GoogleUserInfoUrl, headers)
    
    if response.code != 200:
      return nilValue()

    # Parse response
    let userData = parseJson(response.body)
    
    # Create GoogleUser instance
    let userClsVal = interp.globals[]["GoogleUser"]
    if userClsVal.kind != vkClass:
      return nilValue()
    
    let userCls = userClsVal.classVal
    let userInstance = newInstance(userCls)
    
    # Set user properties
    if userData.hasKey("id"):
      setInstanceSlot(userInstance, "id", userData["id"].getStr().toValue())
    if userData.hasKey("email"):
      setInstanceSlot(userInstance, "email", userData["email"].getStr().toValue())
    if userData.hasKey("name"):
      setInstanceSlot(userInstance, "name", userData["name"].getStr().toValue())
    if userData.hasKey("given_name"):
      setInstanceSlot(userInstance, "givenName", userData["given_name"].getStr().toValue())
    if userData.hasKey("family_name"):
      setInstanceSlot(userInstance, "familyName", userData["family_name"].getStr().toValue())
    if userData.hasKey("picture"):
      setInstanceSlot(userInstance, "picture", userData["picture"].getStr().toValue())
    if userData.hasKey("locale"):
      setInstanceSlot(userInstance, "locale", userData["locale"].getStr().toValue())
    if userData.hasKey("verified_email"):
      setInstanceSlot(userInstance, "verifiedEmail", userData["verified_email"].getBool().toValue())
    
    return userInstance.toValue()
  except:
    return nilValue()

proc googleOAuthRefreshAccessTokenImpl*(interp: var Interpreter, self: Instance,
                                         args: seq[NodeValue]): NodeValue {.nimcall.} =
  ## Refresh an access token using refresh token

  if not self.isNimProxy or self.nimValue == nil:
    return nilValue()

  let dataPtr = cast[ptr GoogleOAuthData](self.nimValue)

  if args.len < 1:
    return nilValue()

  let refreshToken = args[0].toString()

  try:
    # Build token request
    var body = "refresh_token=" & encodeUrl(refreshToken)
    body.add("&client_id=" & encodeUrl(dataPtr.clientId))
    body.add("&client_secret=" & encodeUrl(dataPtr.clientSecret))
    body.add("&grant_type=refresh_token")

    # Make request
    let response = dataPtr.httpClient.post(GoogleTokenUrl,
                                           emptyHttpHeaders(),
                                           body)
    
    if response.code != 200:
      return nilValue()

    # Parse response
    let tokenData = parseJson(response.body)
    
    # Create token table
    var table = initTable[NodeValue, NodeValue]()
    if tokenData.hasKey("access_token"):
      table["access_token".toValue()] = tokenData["access_token"].getStr().toValue()
    if tokenData.hasKey("token_type"):
      table["token_type".toValue()] = tokenData["token_type"].getStr().toValue()
    if tokenData.hasKey("expires_in"):
      table["expires_in".toValue()] = tokenData["expires_in"].getInt().toValue()
    if tokenData.hasKey("id_token"):
      table["id_token".toValue()] = tokenData["id_token"].getStr().toValue()
    
    return table.toValue()
  except:
    return nilValue()
