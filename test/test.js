import { jest } from '@jest/globals';
import XOAuth from '../src/xoauth2.js';

// Mock global fetch
global.fetch = jest.fn();

// Mock crypto API
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

  test('generateCodeVerifier returns a base64url encoded string', async () => {
    const verifier = await xoauth.generateCodeVerifier();
    expect(typeof verifier).toBe('string');
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test('generateCodeChallenge returns a base64url encoded string', async () => {
    const challenge = await xoauth.generateCodeChallenge('testVerifier');
    expect(typeof challenge).toBe('string');
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test('base64UrlEncode returns a correctly encoded string', () => {
    const encoded = xoauth.base64UrlEncode(new Uint8Array([1, 2, 3, 4]));
    expect(encoded).toBe('AQIDBA');
  });

  test('generateState returns a base64url encoded string', () => {
    const state = xoauth.generateState();
    expect(typeof state).toBe('string');
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
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
        profile_image_url: 'https://example.com/image_normal.jpg',
        profile_banner_url: 'https://example.com/banner.jpg'
      }
    };

    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockTokenResponse)
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockUserResponse)
      });

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
    xoauth.session = {
      user: {
        accessToken: 'testAccessToken'
      }
    };

    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({})
    });

    await xoauth.logout();

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(xoauth.session.user).toBeUndefined();
    expect(xoauth.codeVerifier).toBeUndefined();
  });

  test('sendRequest handles GET requests correctly', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ data: 'testData' })
    });

    const result = await xoauth.sendRequest('GET', 'test', { param: 'value' });

    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.x.com/2/test?param=value',
      expect.objectContaining({ method: 'GET' })
    );
    expect(result).toEqual({ data: 'testData' });
  });

  test('sendRequest handles POST requests correctly', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ data: 'testData' })
    });

    const result = await xoauth.sendRequest('POST', 'test', { param: 'value' });

    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.x.com/2/test',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ param: 'value' }),
        headers: expect.objectContaining({ 'Content-Type': 'application/json' })
      })
    );
    expect(result).toEqual({ data: 'testData' });
  });

  test('refreshToken updates session with new tokens', async () => {
    xoauth.session = {
      user: {
        refreshToken: 'oldRefreshToken'
      }
    };

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

  describe('Error Handling', () => {
    test('handleCallback throws error on invalid response', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ error: 'Invalid request' })
      });

      await expect(xoauth.handleCallback('invalidCode', mockSession))
        .rejects.toThrow('Authentication failed');
    });

    test('sendRequest handles network errors', async () => {
      global.fetch.mockRejectedValueOnce(new Error('Network error'));

      await expect(xoauth.sendRequest('GET', 'test'))
        .rejects.toThrow('Network error');
    });
  });

  describe('Rate Limiting', () => {
    test('sendRequest throws error on rate limit', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        json: () => Promise.resolve({ error: 'Rate limit exceeded' })
      });

      await expect(xoauth.sendRequest('GET', 'test'))
        .rejects.toThrow('Rate limit exceeded');
    });
  });

  describe('HTTP Methods', () => {
    test('patch method sends PATCH request', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: 'testData' })
      });

      await xoauth.patch('test', { param: 'value' });

      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.x.com/2/test',
        expect.objectContaining({
          method: 'PATCH',
          body: JSON.stringify({ param: 'value' }),
          headers: expect.objectContaining({ 'Content-Type': 'application/json' })
        })
      );
    });

    // Similar tests for put and delete methods...
  });
});