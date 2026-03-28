# harding-google-oauth

Google OAuth2 wrapper for Harding - provides easy Google authentication for web applications.

## Features

- Pre-configured Google OAuth2 endpoints
- Support for Authorization Code Grant with PKCE
- ID token verification (JWT)
- User profile retrieval
- Token refresh
- Multiple scopes support (Gmail, Drive, Calendar, etc.)

## Installation

Install dependencies:
```bash
nimble install jwt curly
```

Clone and install:
```bash
cd /path/to/harding/external
git clone https://github.com/gokr/harding-google-oauth.git
cd harding-google-oauth
```

Add to registry and install:
```bash
cd /path/to/harding
./harding lib install googleoauth
nimble harding
```

## Usage

### Basic Google Login Flow

```harding
#!/usr/bin/env harding
#
# Google OAuth Example
#

Harding load: "lib/googleoauth/Bootstrap.hrd".

# Create Google OAuth client
google := GoogleOAuth 
    clientId: "your-google-client-id.apps.googleusercontent.com"
    clientSecret: "your-google-client-secret"
    redirectUri: "http://localhost:8080/callback".

# Get authorization URL
authUrl := google getAuthorizationUrl: (GoogleOAuth scopeBasic).
"Please visit: " print. authUrl print.

# After user authorizes and redirects back with code:
code := "authorization-code-from-callback".

# Exchange code for tokens
tokens := google exchangeCode: code.
tokens notNil ifTrue: [
    accessToken := tokens at: "access_token".
    refreshToken := tokens at: "refresh_token".
    idToken := tokens at: "id_token".
    
    "Access Token: " print. accessToken print.
    "ID Token: " print. idToken print.
    
    # Verify ID token
    verified := google verifyIdToken: idToken.
    verified notNil ifTrue: [
        "Token verified for: " print. (verified at: "email") print.
    ].
    
    # Get user info
    user := google getUserInfo: accessToken.
    user notNil ifTrue: [
        "Welcome, " print. user displayName print.
        "Email: " print. user email print.
        "Picture: " print. user picture print.
    ].
].
```

### Available Scopes

```harding
GoogleOAuth scopeOpenid     # "openid"
GoogleOAuth scopeEmail      # "email"
GoogleOAuth scopeProfile    # "profile"
GoogleOAuth scopeBasic      # "openid email profile"
GoogleOAuth scopeDrive      # "https://www.googleapis.com/auth/drive"
GoogleOAuth scopeCalendar   # "https://www.googleapis.com/auth/calendar"
GoogleOAuth scopeSheets     # "https://www.googleapis.com/auth/spreadsheets"
```

### Token Refresh

```harding
# When access token expires
newTokens := google refreshAccessToken: refreshToken.
newTokens notNil ifTrue: [
    newAccessToken := newTokens at: "access_token".
    "New access token: " print. newAccessToken print.
].
```

### Using PKCE (for mobile/SPA apps)

```harding
# Get auth URL with PKCE
authUrl := google getAuthorizationUrl: (GoogleOAuth scopeBasic) usePKCE: true.

# Exchange code (PKCE verifier handled automatically)
tokens := google exchangeCode: code.
```

## API Reference

### GoogleOAuth Class

#### Class Methods

- `GoogleOAuth class>>new` - Create new instance
- `GoogleOAuth class>>clientId: clientSecret: redirectUri:` - Create with credentials
- `GoogleOAuth class>>scopeOpenid`, `scopeEmail`, `scopeProfile`, `scopeBasic`, `scopeDrive`, `scopeCalendar`, `scopeSheets` - Predefined scopes

#### Instance Methods

- `google getAuthorizationUrl: scope` - Get authorization URL
- `google getAuthorizationUrl: scope usePKCE: usePKCE` - Get URL with PKCE
- `google exchangeCode: code` - Exchange code for tokens
- `google verifyIdToken: idToken` - Verify ID token
- `google getUserInfo: accessToken` - Get user profile
- `google refreshAccessToken: refreshToken` - Refresh access token

### GoogleUser Class

Properties (auto-generated accessors):
- `user id` - Google user ID
- `user email` - Email address
- `user name` - Full name
- `user givenName` - First name
- `user familyName` - Last name
- `user picture` - Profile picture URL
- `user locale` - Locale (e.g., "en")
- `user verifiedEmail` - Email verified status

Methods:
- `user isVerified` - Check if email is verified
- `user displayName` - Get best display name

## Requirements

- Nim >= 2.0.0
- Harding >= 0.6.0
- jwt >= 0.2.0
- curly >= 1.1.0
- Google OAuth2 credentials (client ID and secret)

## Setup Google OAuth2 Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Go to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Configure consent screen if needed
6. Select application type (Web application)
7. Add authorized redirect URIs (e.g., `http://localhost:8080/callback`)
8. Save client ID and client secret

## License

MIT License - See LICENSE file for details.

## Credits

Built on top of:
- [nim-jwt](https://github.com/yglukhov/nim-jwt) by yglukhov
- [curly](https://github.com/guzba/curly) by guzba
