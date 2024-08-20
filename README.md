# XOXOAuth2

A simple library for X (Twitter) OAuth 2.0 Authentication.

## Node.js Version Requirements

This XOXOAuth2 library requires a minimum Node.js version of 18.0.0 due to its use of the global Fetch API and Web Crypto API without additional polyfills.

- **Minimum version**: 18.0.0
- **Recommended version**: Latest LTS version (20.x as of August 2024)

To check your Node.js version, run:

```bash
node --version
```

Make sure you're using a compatible version before installing and using this library.

## Installation

To install the XOXOAuth2 library, run the following command in your project directory:

```bash
npm install roman-lxix/xoxoauth2
```

## Usage

Here's a simplified example of how to use the XO-Auth library for authentication in your JavaScript project:

1. Import the library:

```javascript
const XOAuth = require("xoxoauth2")
```

2. Initialize the XOAuth client:

```javascript
const xoAuth = new XOAuth(
	"YOUR_CLIENT_ID",
	"YOUR_CLIENT_SECRET",
	"YOUR_REDIRECT_URI"
)
```

3. Generate the authorization URL:

```javascript
const session = {} // Use your session management solution
// You can also pass req.session into methods that require
// the session parameter from an express.js route

async function login() {
	const authUrl = await xoAuth.getAuthorizationURL(session)
	// Redirect the user to authUrl for authentication or create a link ot it
}
```

4. Handle the OAuth callback:

```javascript
async function handleCallback(code) {
	try {
		const userData = await xoAuth.handleCallback(code, session)
		// Store userData in your session or database
		// Redirect the user to a protected route or display data
	} catch (error) {
		console.error("Authentication failed:", error.message)
		// Handle the error, redirect to login
	}
}
```

5. Make authenticated requests:

```javascript
async function fetchTweets() {
	try {
		const tweetData = await xoAuth.get(
			//endpoint example goes to https://api.x.com/2/tweets
			"tweets",
			// Parameters
			{ ids: "tweet_id" },
			// Headers -- always pass the Bearer token if available
			{ Authorization: `Bearer ${session.user.accessToken}` }
		)
		// Display or process the tweetData
	} catch (error) {
		console.error("Request failed:", error.message)
		// Handle the error
	}
}
```

6. Logout:

```javascript
async function logout() {
	try {
		await xoAuth.logout(session)
		// Clear user data from your session
		// Redirect the user to the login page
	} catch (error) {
		console.error("Logout failed:", error.message)
		// Handle the error
	}
}
```

The library automatically refreshes tokens when needed, but you may also do so with the refreshToken method

```javascript
async function refreshAccessToken() {
	try {
		await xoAuth.refreshToken()
		// The session.user object is updated with the new access token
		console.log("Access token refreshed successfully")
	} catch (error) {
		console.error("Token refresh failed:", error.message)
		// Handle the error, such as redirecting to login
	}
}
```

## Error Handling

The library throws errors for various scenarios. Always wrap your calls in try-catch blocks:

```javascript
try {
	// XOAuth method calls
} catch (error) {
	console.error("XOAuth error:", error.message)
	// Handle the error appropriately
}
```

## Security Considerations

- Always store your client secret securely and never expose it to the client-side.
- Use HTTPS for all OAuth-related communications.
- The library implements CSRF protection using the state parameter in the authorization URL.
- Ensure proper session management to securely store and handle user tokens.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is released under the Creative Commons Zero (CC0) 1.0 Universal license.

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
