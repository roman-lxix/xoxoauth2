const XOAuth = require('./xoauth2');

// Generate a valid mock client ID
const generateValidMockClientId = () => {
	const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
	let clientId = '';
	for (let i = 0; i < 34; i++) {
		clientId += base64Chars.charAt(Math.floor(Math.random() * base64Chars.length));
	}
	return clientId;
};

// Generate a valid mock client secret
const generateValidMockClientSecret = () => {
	const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
	let clientSecret = '';
	for (let i = 0; i < 50; i++) {
		clientSecret += base64Chars.charAt(Math.floor(Math.random() * base64Chars.length));
	}
	return clientSecret;
};

describe('XOAuth', () => {
    let xoauth;
    let mockClientId;
    let mockClientSecret;
    const mockRedirectUri = 'http://localhost:3000/callback';
    const mockSessionUpdateCallback = jest.fn();

    beforeEach(() => {
        mockClientId = generateValidMockClientId();
        mockClientSecret = generateValidMockClientSecret();
        xoauth = new XOAuth(mockClientId, mockClientSecret, mockRedirectUri, mockSessionUpdateCallback);
    });

    describe('Constructor', () => {
        test('sets clientId correctly', () => {
            expect(xoauth.clientId).toBe(mockClientId);
            expect(xoauth.clientId).toMatch(/^[a-zA-Z0-9._-]+$/);
            expect(xoauth.clientId.length).toBe(34);
        });

        test('sets clientSecret correctly', () => {
            expect(xoauth.clientSecret).toBe(mockClientSecret);
            expect(xoauth.clientSecret).toMatch(/^[a-zA-Z0-9._-]+$/);
            expect(xoauth.clientSecret.length).toBe(50);
        });

        test('sets redirectUri correctly', () => {
            expect(xoauth.redirectUri).toBe(mockRedirectUri);
            expect(() => new URL(xoauth.redirectUri)).not.toThrow();
        });

        test('sets sessionUpdateCallback correctly', () => {
            expect(xoauth.sessionUpdateCallback).toBe(mockSessionUpdateCallback);
            expect(typeof xoauth.sessionUpdateCallback).toBe('function');
        });

        test('sets API_BASE_URL correctly', () => {
            expect(xoauth.API_BASE_URL).toBe('https://api.x.com/2/');
        });

        test('sets AUTH_URL correctly', () => {
            expect(xoauth.AUTH_URL).toBe('https://x.com/i/oauth2/authorize');
        });
    });

    describe('onSessionUpdate method', () => {
        test('updates sessionUpdateCallback', () => {
            const newCallback = jest.fn();
            xoauth.onSessionUpdate(newCallback);
            expect(xoauth.sessionUpdateCallback).toBe(newCallback);
        });
    });

    describe('generateCodeVerifier method', () => {
        test('returns a string', async () => {
            const verifier = await xoauth.generateCodeVerifier();
            expect(typeof verifier).toBe('string');
        });

        test('returns a string of correct length', async () => {
            const verifier = await xoauth.generateCodeVerifier();
            expect(verifier.length).toBe(43); // Base64 encoding of 32 bytes
        });

        test('returns a URL-safe string', async () => {
            const verifier = await xoauth.generateCodeVerifier();
            expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        test('returns different values on subsequent calls', async () => {
            const verifier1 = await xoauth.generateCodeVerifier();
            const verifier2 = await xoauth.generateCodeVerifier();
            expect(verifier1).not.toBe(verifier2);
        });

        test('does not contain padding characters', async () => {
            const verifier = await xoauth.generateCodeVerifier();
            expect(verifier).not.toContain('=');
        });
    });

    describe('generateCodeChallenge method', () => {
        // Add tests for generateCodeChallenge
    });

    describe('getAuthorizationURL method', () => {
        // Add tests for getAuthorizationURL
    });

    describe('handleCallback method', () => {
        // Add tests for handleCallback
    });

    describe('logout method', () => {
        // Add tests for logout
    });

    describe('API request methods', () => {
        describe('get method', () => {
            // Add tests for get
        });

        describe('post method', () => {
            // Add tests for post
        });

        // ... other HTTP methods ...
    });

    describe('refreshToken method', () => {
        // Add tests for refreshToken
    });
});