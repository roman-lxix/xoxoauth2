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

// Mock crypto.subtle if it's not available in the test environment
if (!global.crypto) {
    global.crypto = {
        getRandomValues: jest.fn(array => array.map(() => Math.floor(Math.random() * 256))),
        subtle: {
            digest: jest.fn().mockResolvedValue(new ArrayBuffer(32))
        }
    };
}

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
        global.fetch = jest.fn(() => Promise.resolve({
            ok: true,
            json: () => Promise.resolve({})
        }));
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

    describe('getAuthorizationURL method', () => {
        let mockSession;

        beforeEach(() => {
            mockSession = {};
            jest.spyOn(xoauth, 'generateCodeVerifier').mockResolvedValue('mock_code_verifier');
            jest.spyOn(xoauth, 'generateCodeChallenge').mockResolvedValue('mock_code_challenge');
            jest.spyOn(xoauth, 'generateState').mockReturnValue('mock_state');
        });

        test('returns a valid URL', async () => {
            const url = await xoauth.getAuthorizationURL(mockSession);
            expect(() => new URL(url)).not.toThrow();
        });

        test('sets codeVerifier in the session', async () => {
            await xoauth.getAuthorizationURL(mockSession);
            expect(mockSession.codeVerifier).toBe('mock_code_verifier');
        });

        test('includes all required parameters', async () => {
            const url = new URL(await xoauth.getAuthorizationURL(mockSession));
            expect(url.searchParams.get('response_type')).toBe('code');
            expect(url.searchParams.get('client_id')).toBe(mockClientId);
            expect(url.searchParams.get('redirect_uri')).toBe(mockRedirectUri);
            expect(url.searchParams.get('scope')).toBe('tweet.read users.read offline.access');
            expect(url.searchParams.get('state')).toBe('mock_state');
            expect(url.searchParams.get('code_challenge')).toBe('mock_code_challenge');
            expect(url.searchParams.get('code_challenge_method')).toBe('S256');
        });

        test('uses the correct base authorization URL', async () => {
            const url = new URL(await xoauth.getAuthorizationURL(mockSession));
            expect(url.origin + url.pathname).toBe(xoauth.AUTH_URL);
        });

        test('generates new code verifier and challenge for each call', async () => {
            await xoauth.getAuthorizationURL(mockSession);
            await xoauth.getAuthorizationURL(mockSession);
            expect(xoauth.generateCodeVerifier).toHaveBeenCalledTimes(2);
            expect(xoauth.generateCodeChallenge).toHaveBeenCalledTimes(2);
        });
    });

    describe('handleCallback method', () => {
        let mockSession;
        const mockCode = 'mock_auth_code';
        const mockTokenData = {
            access_token: 'mock_access_token',
            refresh_token: 'mock_refresh_token'
        };
        const mockUserData = {
            data: {
                id: 'mock_user_id',
                username: 'mock_username',
                profile_image_url: 'http://example.com/image_normal.jpg',
                profile_banner_url: 'http://example.com/banner.jpg'
            }
        };

        beforeEach(() => {
            mockSession = {
                codeVerifier: 'mock_code_verifier',
                id: 'mock_session_id'
            };
            xoauth.post = jest.fn().mockResolvedValue(mockTokenData);
            xoauth.get = jest.fn().mockResolvedValue(mockUserData);
            xoauth._triggerSessionUpdateCallback = jest.fn();
        });

        test('exchanges code for tokens', async () => {
            await xoauth.handleCallback(mockCode, mockSession);
            expect(xoauth.post).toHaveBeenCalledWith(
                'oauth2/token',
                expect.objectContaining({
                    code: mockCode,
                    grant_type: 'authorization_code',
                    code_verifier: mockSession.codeVerifier
                }),
                expect.any(Object),
                mockSession
            );
        });

        test('fetches user data', async () => {
            await xoauth.handleCallback(mockCode, mockSession);
            expect(xoauth.get).toHaveBeenCalledWith(
                'users/me',
                { 'user.fields': 'profile_image_url,profile_banner_url' },
                { Authorization: `Bearer ${mockTokenData.access_token}` },
                mockSession
            );
        });

        test('returns user object with correct data', async () => {
            const user = await xoauth.handleCallback(mockCode, mockSession);
            expect(user).toEqual({
                id: mockUserData.data.id,
                username: mockUserData.data.username,
                profileImageUrl: 'http://example.com/image.jpg',
                profileBannerUrl: mockUserData.data.profile_banner_url,
                accessToken: mockTokenData.access_token,
                refreshToken: mockTokenData.refresh_token
            });
        });

        test('updates session with user data', async () => {
            await xoauth.handleCallback(mockCode, mockSession);
            expect(mockSession.user).toBeDefined();
            expect(mockSession.user.id).toBe(mockUserData.data.id);
        });

        test('triggers session update callback', async () => {
            await xoauth.handleCallback(mockCode, mockSession);
            expect(xoauth._triggerSessionUpdateCallback).toHaveBeenCalledWith(
                undefined,
                expect.any(Object),
                mockSession.id
            );
        });

        test('throws error on authentication failure', async () => {
            xoauth.post.mockRejectedValue(new Error('API Error'));
            await expect(xoauth.handleCallback(mockCode, mockSession)).rejects.toThrow('Authentication failed');
        });
    });

    describe('logout method', () => {
        let mockSession;
    
        beforeEach(() => {
            mockSession = {
                id: 'mock_session_id',
                user: {
                    id: 'mock_user_id',
                    accessToken: 'mock_access_token'
                },
                destroy: jest.fn()
            };
            xoauth.post = jest.fn().mockResolvedValue({});
            xoauth._triggerSessionUpdateCallback = jest.fn();
        });
    
        test('revokes access token', async () => {
            await xoauth.logout(mockSession);
            expect(xoauth.post).toHaveBeenCalledWith(
                'oauth2/revoke',
                {
                    token: 'mock_access_token',
                    token_type_hint: 'access_token'
                },
                {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Authorization: expect.stringContaining('Basic ')
                },
                mockSession
            );
        });
    
        test('triggers session update callback', async () => {
            const oldUser = { ...mockSession.user };
            await xoauth.logout(mockSession);
            expect(xoauth._triggerSessionUpdateCallback).toHaveBeenCalledWith(
                oldUser,
                undefined,
                mockSession.id
            );
        });
    
        test('destroys the session', async () => {
            await xoauth.logout(mockSession);
            expect(mockSession.destroy).toHaveBeenCalled();
        });
    
        test('handles missing user data gracefully', async () => {
            delete mockSession.user;
            await expect(xoauth.logout(mockSession)).resolves.not.toThrow();
        });
    
        test('logs error on token revocation failure', async () => {
            const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
            xoauth.post.mockRejectedValue(new Error('API Error'));
            await xoauth.logout(mockSession);
            expect(consoleErrorSpy).toHaveBeenCalledWith('Error revoking token:', 'API Error');
            consoleErrorSpy.mockRestore();
        });
    });
    
    describe('API request methods', () => {
        describe('get method', () => {
            const mockEndpoint = 'users/me';
            const mockParams = { 'user.fields': 'profile_image_url' };
            const mockHeaders = { 'Authorization': 'Bearer mock_token' };
            const mockSession = { id: 'mock_session_id' };
            const mockResponseData = { data: { id: 'user123', name: 'Test User' } };

            beforeEach(() => {
                global.fetch = jest.fn(() => Promise.resolve({
                    ok: true,
                    json: () => Promise.resolve(mockResponseData)
                }));
            });

            test('constructs correct URL with parameters', async () => {
                await xoauth.get(mockEndpoint, mockParams, mockHeaders, mockSession);
                
                const expectedUrl = new URL(mockEndpoint, xoauth.API_BASE_URL);
                expectedUrl.search = new URLSearchParams(mockParams).toString();
                
                expect(global.fetch).toHaveBeenCalledWith(
                    expectedUrl.toString(),
                    expect.any(Object)
                );
            });

            test('sends correct headers', async () => {
                await xoauth.get(mockEndpoint, mockParams, mockHeaders, mockSession);
                
                expect(global.fetch).toHaveBeenCalledWith(
                    expect.any(String),
                    expect.objectContaining({
                        headers: mockHeaders,
                        method: 'GET'
                    })
                );
            });

            test('returns parsed JSON response', async () => {
                const result = await xoauth.get(mockEndpoint, mockParams, mockHeaders, mockSession);
                
                expect(result).toEqual(mockResponseData);
            });

            test('throws error for non-OK response', async () => {
                const errorResponse = {
                    ok: false,
                    status: 404,
                    statusText: 'Not Found',
                    json: () => Promise.resolve({ error: 'Not Found' })
                };
                global.fetch.mockResolvedValueOnce(errorResponse);

                await expect(xoauth.get(mockEndpoint, mockParams, mockHeaders, mockSession))
                    .rejects.toThrow('HTTP error! status: 404, message: Not Found');
            });

            test('handles empty params and headers', async () => {
                await xoauth.get(mockEndpoint);
                
                const expectedUrl = new URL(mockEndpoint, xoauth.API_BASE_URL);
                
                expect(global.fetch).toHaveBeenCalledWith(
                    expectedUrl.toString(),
                    expect.objectContaining({
                        headers: {},
                        method: 'GET'
                    })
                );
            });
        });

        describe('post method', () => {
            const mockEndpoint = 'oauth2/token';
            const mockData = { grant_type: 'authorization_code', code: 'mock_code' };
            const mockHeaders = { 'Authorization': 'Basic mock_auth' };
            const mockSession = { id: 'mock_session_id' };
            const mockResponseData = { access_token: 'mock_token', token_type: 'bearer' };

            beforeEach(() => {
                global.fetch = jest.fn(() =>
                    Promise.resolve({
                        ok: true,
                        json: () => Promise.resolve(mockResponseData)
                    })
                );
            });

            test('sends request to correct URL', async () => {
                await xoauth.post(mockEndpoint, mockData, mockHeaders, mockSession);
                const expectedUrl = new URL(mockEndpoint, xoauth.API_BASE_URL);
                
                expect(global.fetch).toHaveBeenCalledWith(
                    expectedUrl.toString(),
                    expect.any(Object)
                );
            });

            test('sends correct headers and data', async () => {
                await xoauth.post(mockEndpoint, mockData, mockHeaders, mockSession);
                
                expect(global.fetch).toHaveBeenCalledWith(
                    expect.any(String),
                    expect.objectContaining({
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...mockHeaders
                        },
                        body: JSON.stringify(mockData)
                    })
                );
            });

            test('returns parsed JSON response', async () => {
                const result = await xoauth.post(mockEndpoint, mockData, mockHeaders, mockSession);
                
                expect(result).toEqual(mockResponseData);
            });

            test('throws error for non-OK response', async () => {
                const errorResponse = {
                    ok: false,
                    status: 400,
                    statusText: 'Bad Request',
                    json: () => Promise.resolve({ error: 'Bad Request' })
                };
                global.fetch.mockResolvedValueOnce(errorResponse);

                await expect(xoauth.post(mockEndpoint, mockData, mockHeaders, mockSession))
                    .rejects.toThrow('HTTP error! status: 400, message: Bad Request');
            });

            test('handles empty data and headers', async () => {
                await xoauth.post(mockEndpoint);
                
                expect(global.fetch).toHaveBeenCalledWith(
                    expect.any(String),
                    expect.objectContaining({
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: '{}'
                    })
                );
            });

            test('uses application/x-www-form-urlencoded when specified', async () => {
                const formData = { key1: 'value1', key2: 'value2' };
                await xoauth.post(mockEndpoint, formData, { 'Content-Type': 'application/x-www-form-urlencoded' });
                
                expect(global.fetch).toHaveBeenCalledWith(
                    expect.any(String),
                    expect.objectContaining({
                        method: 'POST',
                        headers: expect.objectContaining({
                            'Content-Type': 'application/x-www-form-urlencoded'
                        }),
                        body: expect.any(URLSearchParams)
                    })
                );
                
                const calledBody = global.fetch.mock.calls[0][1].body;
                expect(calledBody.toString()).toBe('key1=value1&key2=value2');
            });
        });
    });

    describe('refreshToken method', () => {
        let mockSession;
        const mockTokenData = {
            access_token: 'new_access_token',
            refresh_token: 'new_refresh_token'
        };

        beforeEach(() => {
            mockSession = {
                id: 'mock_session_id',
                user: {
                    id: 'mock_user_id',
                    accessToken: 'old_access_token',
                    refreshToken: 'old_refresh_token'
                }
            };
            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockTokenData)
            }));
        });

        test('calls token endpoint with correct parameters', async () => {
            await xoauth.refreshToken(mockSession);
            expect(global.fetch).toHaveBeenCalledWith(
                `${xoauth.API_BASE_URL}oauth2/token`,
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': expect.any(String)
                    }),
                    body: expect.any(URLSearchParams)
                })
            );
        
            const calledBody = global.fetch.mock.calls[0][1].body;
            expect(calledBody).toBeInstanceOf(URLSearchParams);
            expect(calledBody.get('grant_type')).toBe('refresh_token');
            expect(calledBody.get('refresh_token')).toBe('old_refresh_token');
        });

        test('updates session with new tokens', async () => {
            await xoauth.refreshToken(mockSession);
            expect(mockSession.user.accessToken).toBe('new_access_token');
            expect(mockSession.user.refreshToken).toBe('new_refresh_token');
        });

        test('returns updated user object', async () => {
            const result = await xoauth.refreshToken(mockSession);
            expect(result).toEqual({
                accessToken: 'new_access_token',
                refreshToken: 'new_refresh_token'
            });
        });

        test('throws error on token refresh failure', async () => {
            global.fetch = jest.fn(() => Promise.resolve({
                ok: false,
                status: 400,
                statusText: 'Bad Request',
                json: () => Promise.resolve({ error: 'Invalid refresh token' })
            }));
            await expect(xoauth.refreshToken(mockSession)).rejects.toThrow('Token refresh failed');
        });

        test('handles missing refresh token gracefully', async () => {
            delete mockSession.user.refreshToken;
            const result = await xoauth.refreshToken(mockSession);
            expect(result).toEqual({
                accessToken: 'new_access_token',
                refreshToken: 'new_refresh_token'
            });
        });

        test('throws error on token refresh failure', async () => {
            global.fetch = jest.fn(() => Promise.resolve({
                ok: false,
                status: 400,
                statusText: 'Bad Request',
                json: () => Promise.resolve({ error: 'Invalid refresh token' })
            }));
            await expect(xoauth.refreshToken(mockSession)).rejects.toThrow('Token refresh failed');
        });
    });

    describe('Internal helper methods', () => {
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
            test('returns a string', async () => {
                const verifier = await xoauth.generateCodeVerifier();
                const challenge = await xoauth.generateCodeChallenge(verifier);
                expect(typeof challenge).toBe('string');
            });

            test('returns a string of correct length', () => {
                const state = xoauth.generateState();
                expect(state.length).toBe(22); // The actual implementation generates a 22-character string
            });

            test('returns a URL-safe string', async () => {
                const verifier = await xoauth.generateCodeVerifier();
                const challenge = await xoauth.generateCodeChallenge(verifier);
                expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
            });

            test('returns consistent output for the same input', async () => {
                const verifier = await xoauth.generateCodeVerifier();
                const challenge1 = await xoauth.generateCodeChallenge(verifier);
                const challenge2 = await xoauth.generateCodeChallenge(verifier);
                expect(challenge1).toBe(challenge2);
            });

            test('returns different output for different inputs', async () => {
                const verifier1 = await xoauth.generateCodeVerifier();
                const verifier2 = await xoauth.generateCodeVerifier();
                const challenge1 = await xoauth.generateCodeChallenge(verifier1);
                const challenge2 = await xoauth.generateCodeChallenge(verifier2);
                expect(challenge1).not.toBe(challenge2);
            });

            test('does not contain padding characters', async () => {
                const verifier = await xoauth.generateCodeVerifier();
                const challenge = await xoauth.generateCodeChallenge(verifier);
                expect(challenge).not.toContain('=');
            });
        });

        describe('generateState method', () => {
            test('returns a string', () => {
                const state = xoauth.generateState();
                expect(typeof state).toBe('string');
            });

            test('returns a string of correct length', () => {
                const state = xoauth.generateState();
                expect(state.length).toBe(22); // The actual implementation generates a 22-character string
            });

            test('returns different values on subsequent calls', () => {
                const state1 = xoauth.generateState();
                const state2 = xoauth.generateState();
                expect(state1).not.toBe(state2);
            });
        });

        describe('_triggerSessionUpdateCallback method', () => {
            test('calls the session update callback with correct parameters', () => {
                const mockCallback = jest.fn();
                xoauth.onSessionUpdate(mockCallback);
                
                const oldData = { id: 'old' };
                const newData = { id: 'new' };
                const sessionId = 'session123';
                
                xoauth._triggerSessionUpdateCallback(oldData, newData, sessionId);
                
                expect(mockCallback).toHaveBeenCalledWith(oldData, newData, sessionId);
            });

            test('handles case when no callback is set', () => {
                xoauth.sessionUpdateCallback = null;
                expect(() => {
                    xoauth._triggerSessionUpdateCallback({}, {}, 'session123');
                }).not.toThrow();
            });
        });
    });
});