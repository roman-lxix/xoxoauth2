/**
 * XOAuth class for handling OAuth 2.0 authentication with X (formerly Twitter) API.
 */
class XOAuth {
	/**
	 * Create an XOAuth instance.
	 * @param {string} clientId - The OAuth 2.0 client ID.
	 * @param {string} clientSecret - The OAuth 2.0 client secret.
	 * @param {string} redirectUri - The redirect URI for the OAuth flow.
	 */
	constructor(clientId, clientSecret, redirectUri, session) {
		this.clientId = clientId
		this.clientSecret = clientSecret
		this.redirectUri = redirectUri
		this.API_BASE_URL = "https://api.x.com/2/"
		;(this.AUTH_URL = "https://x.com/i/oauth2/authorize"),
			(this.session = session)
	}

	/**
	 * Generate a random code verifier for PKCE (Proof Key for Code Exchange).
	 * @returns {Promise<string>} A base64url-encoded random string.
	 */
	async generateCodeVerifier() {
		const array = new Uint8Array(32)
		crypto.getRandomValues(array)
		return this.base64UrlEncode(array)
	}

	/**
	 * Generate a code challenge from the code verifier using SHA-256 hashing.
	 * @param {string} verifier - The code verifier.
	 * @returns {Promise<string>} A base64url-encoded SHA-256 hash of the verifier.
	 */
	async generateCodeChallenge(verifier) {
		const encoder = new TextEncoder()
		const data = encoder.encode(verifier)
		const hash = await crypto.subtle.digest("SHA-256", data)
		return this.base64UrlEncode(new Uint8Array(hash))
	}

	/**
	 * Encode a Uint8Array to a URL-safe base64 string.
	 * @param {Uint8Array} array - The array to encode.
	 * @returns {string} A URL-safe base64 encoded string.
	 */
	base64UrlEncode(array) {
		return btoa(String.fromCharCode.apply(null, array))
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
			.replace(/=/g, "")
	}

	/**
	 * Generate a cryptographically secure random state for CSRF protection.
	 * @returns {string} A base64url-encoded random string.
	 */
	generateState() {
		const array = new Uint8Array(16)
		crypto.getRandomValues(array)
		return this.base64UrlEncode(array)
	}

	/**
	 * Initiate the OAuth flow by generating the authorization URL.
	 * @returns {Promise<string>} The authorization URL.
	 */
	async getAuthorizationURL(session) {
		this.session = session

		const codeVerifier = await this.generateCodeVerifier()
		const codeChallenge = await this.generateCodeChallenge(codeVerifier)

		this.codeVerifier = codeVerifier

		const authorizationURL = new URL(this.AUTH_URL)
		authorizationURL.searchParams.append("response_type", "code")
		authorizationURL.searchParams.append("client_id", this.clientId)
		authorizationURL.searchParams.append("redirect_uri", this.redirectUri)
		authorizationURL.searchParams.append(
			"scope",
			"tweet.read users.read offline.access"
		)
		authorizationURL.searchParams.append("state", this.generateState())
		authorizationURL.searchParams.append("code_challenge", codeChallenge)
		authorizationURL.searchParams.append("code_challenge_method", "S256")

		return authorizationURL.toString()
	}

	/**
	 * Handle the OAuth callback, exchange code for tokens, and fetch user data.
	 * @param {string} code - The authorization code received from the OAuth provider.
	 * @returns {Promise<Object>} The user data including access and refresh tokens.
	 * @throws {Error} If authentication fails.
	 */
	async handleCallback(code, session) {
		try {
			this.session = session

			const tokenData = await this.post(
				"oauth2/token",
				{
					code: code,
					grant_type: "authorization_code",
					client_id: this.clientId,
					redirect_uri: this.redirectUri,
					code_verifier: this.codeVerifier
				},
				{
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization:
						"Basic " + btoa(`${this.clientId}:${this.clientSecret}`)
				}
			)

			const { access_token, refresh_token } = tokenData

			const userData = await this.get(
				"users/me",
				{ "user.fields": "profile_image_url,profile_banner_url" },
				{ Authorization: `Bearer ${access_token}` }
			)

			this.session.user = {
				id: userData.data.id,
				username: userData.data.username,
				profileImageUrl: userData.data.profile_image_url.replace("_normal", ""),
				profileBannerUrl: userData.data.profile_banner_url,
				accessToken: access_token,
				refreshToken: refresh_token
			}

			return this.session.user
		} catch (error) {
			console.error("Error in OAuth callback:", error.message)
			throw new Error("Authentication failed")
		}
	}

	/**
	 * Log out the user by revoking the access token and clearing the session.
	 * @returns {Promise<void>}
	 */
	async logout() {
		if (this.session && this.session.user && this.session.user.accessToken) {
			try {
				await this.post(
					"oauth2/revoke",
					{
						token: this.session.user.accessToken,
						token_type_hint: "access_token"
					},
					{
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization:
							"Basic " + btoa(`${this.clientId}:${this.clientSecret}`)
					}
				)

				console.log("Token revoked successfully")
			} catch (error) {
				console.error("Error revoking token:", error.message)
			}
		}

		// Clear the user data and code verifier from the session
		delete this.session.user
		delete this.codeVerifier
	}

	/**
	 * Send an HTTP request to the API.
	 * @param {string} method - The HTTP method (GET, POST, etc.).
	 * @param {string} url - The API endpoint.
	 * @param {Object} [data={}] - The request data.
	 * @param {Object} [headers={}] - Additional headers.
	 * @returns {Promise<Object>} The parsed JSON response.
	 * @throws {Error} If the request fails or returns an error status.
	 */
	async sendRequest(method, url, data = {}, headers = {}) {
		url = this.API_BASE_URL + url

		const options = {
			method,
			headers: {
				...headers
			}
		}

		if (method === "GET" && Object.keys(data).length) {
			const params = new URLSearchParams(data)
			url += `?${params}`
		} else if (method !== "GET") {
			if (headers["Content-Type"] === "application/x-www-form-urlencoded") {
				options.body = new URLSearchParams(data)
			} else {
				options.body = JSON.stringify(data)
				options.headers["Content-Type"] = "application/json"
			}
		}

		let response = await fetch(url, options)

		if (
			response.status === 401 &&
			this.session &&
			this.session.user &&
			this.session.user.refreshToken
		) {
			try {
				await this.refreshToken()
				// Update the headers with the new access token
				options.headers.Authorization = `Bearer ${this.session.user.accessToken}`
				// Retry the request
				response = await fetch(url, options)
			} catch (error) {
				console.error("Token refresh failed:", error)
				throw new Error("Authentication failed")
			}
		}

		if (response.status === 429) {
			throw new Error(`Rate limit exceeded. Status: ${response.status}`)
		}

		if (!response.ok) {
			const errorData = await response.json()
			throw new Error(
				`HTTP error! status: ${response.status}, message: ${errorData.error}`
			)
		}

		//console.log(this.session)

		return response.json()
	}

	/**
	 * Refresh the access token using the refresh token.
	 * @returns {Promise<void>}
	 * @throws {Error} If token refresh fails.
	 */
	async refreshToken() {
		try {
			const response = await fetch(this.API_BASE_URL + "oauth2/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization:
						"Basic " + btoa(`${this.clientId}:${this.clientSecret}`)
				},
				body: new URLSearchParams({
					refresh_token: this.session.user.refreshToken,
					grant_type: "refresh_token",
					client_id: this.clientId
				})
			})

			if (!response.ok) {
				throw new Error(`HTTP error! status: ${response.status}`)
			}

			const tokenData = await response.json()

			this.session.user.accessToken = tokenData.access_token
			this.session.user.refreshToken = tokenData.refresh_token
		} catch (error) {
			console.error("Error refreshing token:", error.message)
			throw new Error("Token refresh failed")
		}
	}

	/**
	 * Send a GET request to the API.
	 * @param {string} url - The API endpoint.
	 * @param {Object} [data={}] - Query parameters.
	 * @param {Object} [headers={}] - Additional headers.
	 * @returns {Promise<Object>} The parsed JSON response.
	 */
	async get(url, data = {}, headers = {}) {
		return this.sendRequest("GET", url, data, headers)
	}

	/**
	 * Send a POST request to the API.
	 * @param {string} url - The API endpoint.
	 * @param {Object} [data={}] - The request body.
	 * @param {Object} [headers={}] - Additional headers.
	 * @returns {Promise<Object>} The parsed JSON response.
	 */
	async post(url, data = {}, headers = {}) {
		return this.sendRequest("POST", url, data, headers)
	}

	/**
	 * Send a PATCH request to the API.
	 * @param {string} url - The API endpoint.
	 * @param {Object} [data={}] - The request body.
	 * @param {Object} [headers={}] - Additional headers.
	 * @returns {Promise<Object>} The parsed JSON response.
	 */
	async patch(url, data = {}, headers = {}) {
		return this.sendRequest("PATCH", url, data, headers)
	}

	/**
	 * Send a PUT request to the API.
	 * @param {string} url - The API endpoint.
	 * @param {Object} [data={}] - The request body.
	 * @param {Object} [headers={}] - Additional headers.
	 * @returns {Promise<Object>} The parsed JSON response.
	 */
	async put(url, data = {}, headers = {}) {
		return this.sendRequest("PUT", url, data, headers)
	}

	/**
	 * Send a DELETE request to the API.
	 * @param {string} endpoint - The API endpoint.
	 * @param {Object} [data={}] - The request body.
	 * @param {Object} [headers={}] - Additional headers.
	 * @returns {Promise<Object>} The parsed JSON response.
	 */
	async delete(endpoint, data = {}, headers = {}) {
		return this.sendRequest("DELETE", endpoint, data, headers)
	}
}
export default XOAuth;

// For CommonJS compatibility (optional)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = XOAuth;
}