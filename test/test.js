import { jest } from '@jest/globals';
import XOAuth, { AuthenticationError, NetworkError, RateLimitError } from '../src/xoauth2.js';

jest.setTimeout(30000); // Global timeout

global.fetch = jest.fn();
global.crypto = {
  getRandomValues: jest.fn(array => array.fill(1)),
  subtle: {
    digest: jest.fn(() => Promise.resolve(new ArrayBuffer(32)))
  }
};

describe('XOAuth', () => {
  let xoauth;
  const mockClientId = 'testClientId';
  const mockClientSecret = 'testClientSecret';
  const mockRedirectUri = 'https://example.com/callback';
  const mockSession = {};

  beforeEach(() => {
    xoauth = new XOAuth(mockClientId, mockClientSecret, mockRedirectUri, mockSession);
    global.fetch.mockClear();
  });

  test('constructor initializes properties correctly', () => {
    expect(xoauth.clientId).toBe(mockClientId);
    expect(xoauth.clientSecret).toBe(mockClientSecret);
    expect(xoauth.redirectUri).toBe(mockRedirectUri);
    expect(xoauth.API_BASE_URL).toBe("https://api.x.com/2/");
    expect(xoauth.AUTH_URL).toBe("https://x.com/i/oauth2/authorize");
    expect(xoauth.session).toBe(mockSession);
  });

  test('generateCodeVerifier and generateCodeChallenge return base64url encoded strings', async () => {
    const verifier = await xoauth.generateCodeVerifier();
    const challenge = await xoauth.generateCodeChallenge(verifier);
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test('base64UrlEncode returns a correctly encoded string', () => {
    expect(xoauth.base64UrlEncode(new Uint8Array([1, 2, 3, 4]))).toBe('AQIDBA');
  });

  test('generateState returns a base64url encoded string', () => {
    expect(xoauth.generateState()).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test('getAuthorizationURL returns a valid URL', async () => {
    const url = await xoauth.getAuthorizationURL(mockSession);
    expect(url).toMatch(/^https:\/\/x\.com\/i\/oauth2\/authorize\?/);
    expect(url).toContain(`client_id=${mockClientId}`);
    expect(url).toContain(`redirect_uri=${encodeURIComponent(mockRedirectUri)}`);
  });

  test('handleCallback processes OAuth callback correctly', async () => {
    const mockCode = 'testCode';
    const mockTokenResponse = {
      access_token: 'testAccessToken',
      refresh_token: 'testRefreshToken'
    };
    const mockUserResponse = {
      data: {
        id: 'testUserId',
        username: 'testUsername',
        profile_image_url: 'https://example.com/image.jpg',
        profile_banner_url: 'https://example.com/banner.jpg'
      }
    };

    global.fetch
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(mockTokenResponse) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(mockUserResponse) });

    const user = await xoauth.handleCallback(mockCode, mockSession);

    expect(user).toEqual({
      id: 'testUserId',
      username: 'testUsername',
      profileImageUrl: 'https://example.com/image.jpg',
      profileBannerUrl: 'https://example.com/banner.jpg',
      accessToken: 'testAccessToken',
      refreshToken: 'testRefreshToken'
    });
  });

  test('logout revokes token and clears session', async () => {
    xoauth.session = { user: { accessToken: 'testAccessToken' } };
    global.fetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({}) });

    await xoauth.logout();

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(xoauth.session.user).toBeUndefined();
    expect(xoauth.codeVerifier).toBeUndefined();
  });

  test('sendRequest handles GET and POST requests correctly', async () => {
    global.fetch.mockResolvedValue({ ok: true, json: () => Promise.resolve({ data: 'testData' }) });

    const getResult = await xoauth.sendRequest('GET', 'test', { param: 'value' });
    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.x.com/2/test?param=value',
      expect.objectContaining({ method: 'GET' })
    );
    expect(getResult).toEqual({ data: 'testData' });

    const postResult = await xoauth.sendRequest('POST', 'test', { param: 'value' });
    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.x.com/2/test',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ param: 'value' }),
        headers: expect.objectContaining({ 'Content-Type': 'application/json' })
      })
    );
    expect(postResult).toEqual({ data: 'testData' });
  });

  test('refreshToken updates session with new tokens', async () => {
    xoauth.session = { user: { refreshToken: 'oldRefreshToken' } };
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'newAccessToken',
        refresh_token: 'newRefreshToken'
      })
    });

    await xoauth.refreshToken();

    expect(xoauth.session.user.accessToken).toBe('newAccessToken');
    expect(xoauth.session.user.refreshToken).toBe('newRefreshToken');
  });

  describe('Error Handling and Rate Limiting', () => {
    beforeEach(() => {
      jest.spyOn(xoauth, 'retryWithExponentialBackoff').mockImplementation(async (operation) => operation());
    });

    test('handleCallback throws AuthenticationError on invalid response', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ error: 'Invalid request' })
      });

      await expect(xoauth.handleCallback('invalidCode', mockSession)).rejects.toThrow(AuthenticationError);
    });

    test('sendRequest throws NetworkError on network failure', async () => {
      global.fetch.mockRejectedValueOnce(new Error('Network error'));
      await expect(xoauth.sendRequest('GET', 'test')).rejects.toThrow(NetworkError);
    });

    test('sendRequest throws RateLimitError on rate limit', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        json: () => Promise.resolve({ error: 'Rate limit exceeded' })
      });
      await expect(xoauth.sendRequest('GET', 'test')).rejects.toThrow(RateLimitError);
    });

    test('refreshToken throws AuthenticationError on failure', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ error: 'Invalid refresh token' })
      });
      xoauth.session = { user: { refreshToken: 'invalidToken' } };
      await expect(xoauth.refreshToken()).rejects.toThrow(AuthenticationError);
    });
  });

  describe('HTTP Methods', () => {
    ['patch', 'put', 'delete'].forEach(method => {
      test(`${method} method sends ${method.toUpperCase()} request`, async () => {
        global.fetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: 'testData' })
        });

        await xoauth[method]('test', { param: 'value' });

        expect(global.fetch).toHaveBeenCalledWith(
          'https://api.x.com/2/test',
          expect.objectContaining({
            method: method.toUpperCase(),
            ...(method !== 'delete' && {
              body: JSON.stringify({ param: 'value' }),
              headers: expect.objectContaining({ 'Content-Type': 'application/json' })
            })
          })
        );
      });
    });
  });

  describe('Exponential Backoff', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    test('retries with exponential backoff', async () => {
      const mockOperation = jest.fn()
        .mockRejectedValueOnce(new NetworkError('Connection failed'))
        .mockRejectedValueOnce(new RateLimitError('Rate limit exceeded'))
        .mockResolvedValueOnce('Success');

      const result = xoauth.retryWithExponentialBackoff(mockOperation, 3, 10000);

      await jest.runAllTimersAsync();
      await result;

      expect(mockOperation).toHaveBeenCalledTimes(3);
    });

    test('does not retry on authentication error', async () => {
      const mockOperation = jest.fn().mockRejectedValueOnce(new AuthenticationError('Authentication failed'));
      await expect(xoauth.retryWithExponentialBackoff(mockOperation, 3, 1000)).rejects.toThrow(AuthenticationError);
      expect(mockOperation).toHaveBeenCalledTimes(1);
    });
  });
});