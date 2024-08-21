# XOXOAuth2

XOXOAuth2 is a simple OAuth 2.0 client library for Node.js, designed to work with the X (Twitter) OAuth 2.0 API.

## Installation

```bash
npm install roman-lxix/xoxoauth2
```

## Usage

First, initialize the XOXOAuth2 client:

```javascript
const XOAuth2 = require("xoxoauth2")

const xoAuth = new XOAuth2(
	"YOUR_CLIENT_ID",
	"YOUR_CLIENT_SECRET",
	"http://your/callback/url"
)
```

#### You may use any object for a session, but in this example we assuming an express.js session

Be sure to manage your sessions properly.

### Getting the Authorization URL:

```javascript
const authUrl = await xoAuth.getAuthorizationURL(req.session)
// Redirect the user to authUrl
```

### Handling the Callback from X:

```javascript
await xoAuth.handleCallback(code, req.session)
// User is now authenticated, onSessionUpdate callback will trigger
```

### Making an Authenticated GET Request:

```javascript
const user = await xoAuth.get(
	"users/by/username/lxixthenumber",
	{ "user.fields": "profile_image_url,description" },
	{
		Authorization: `Bearer ${req.session.user.accessToken}`
	},
	session
)
```

### Making an Authenticated POST Request:

```javascript
const tweet = await xoAuth.post(
	"tweets",
	{ text: "Hello, X!" },
	{
		Authorization: `Bearer ${req.session.user.accessToken}`
	},
	session
)
```

### Refreshing the Token

```javascript
await xoAuth.refreshToken(req.session)
// Token has been refreshed, onSessionUpdate callback will trigger
```

### Logging Out

```javascript
await xoAuth.logout(req.session)
// User is now logged out, onSessionUpdate callback will trigger
```

Remember to set up your environment variables (X_CLIENT_ID, X_CLIENT_SECRET) before using the library.

**Note:** For production use, it's highly recommended to implement proper error handling. The examples above omit error handling for brevity, but robust error management is crucial for a reliable application.

## Using onSessionUpdate

The `onSessionUpdate` function is a callback that gets triggered whenever the session data is updated. This can be useful for logging, debugging, or performing additional actions when the session changes.

You can provide this function in two ways:

1. In the constructor:

```javascript
const xoAuth = new XOAuth2(
	"YOUR_CLIENT_ID",
	"YOUR_CLIENT_SECRET",
	"http://your/callback/url",
	(oldData, newData, sessionId) => {
		console.log("Session updated: " + { oldData, newData, sessionId })
	}
)
```

2. By setting it after initialization:

```javascript
xoAuth.onSessionUpdate = (oldData, newData, sessionId) => {
	console.log("Session updated: " + { oldData, newData, sessionId })
}
```

The `onSessionUpdate` function provided in the constructor can be overwritten by setting it after initialization. This allows you to change the behavior dynamically if needed.

## API Reference

### Constructor

```javascript
const xoAuth = new XOAuth2(clientId, clientSecret, redirectUri, onSessionUpdate)
```

- `clientId`: Your X API client ID
- `clientSecret`: Your X API client secret
- `redirectUri`: The callback URL for the OAuth flow
- `onSessionUpdate`: (optional) A function that will be called when the session is updated

### Methods

- `getAuthorizationURL(session)`: Generates the authorization URL for the OAuth flow
- `handleCallback(code, session)`: Handles the callback from the OAuth provider
- `refreshToken(session)`: Refreshes the access token
- `logout(session)`: Logs out the user by clearing the session
- `sendRequest(session)`: Sends a request to the X API

### Convenience Methods

- `get(endpoint, params, headers, session)`: Makes a GET request to the X API
- `post(endpoint, body, headers, session)`: Makes a POST request to the X API
- `put(endpoint, body, headers, session)`: Makes a PUT request to the X API
- `patch(endpoint, body, headers, session)`: Makes a PATCH request to the X API
- `delete(endpoint, body, headers, session)`: Makes a DELETE request to the X API

Session parameters are any object, but an express.js session (req.session) is suitable. A `user` property will be appended to any session object you pass it, and it must contain an `id` property to function properly.

## License

This project is licensed under the Creative Commons Zero v1.0 Universal (CC0-1.0) license. This means you can copy, modify, distribute and perform the work, even for commercial purposes, all without asking permission.

For more information, see [https://creativecommons.org/publicdomain/zero/1.0/](https://creativecommons.org/publicdomain/zero/1.0/)
