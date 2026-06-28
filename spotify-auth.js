/**
 * spotify-auth.js
 * Spotify authentication using the PKCE (Proof Key for Code Exchange) flow.
 *
 * WHY PKCE?
 * - No Client Secret is ever stored or sent from the browser
 * - Spotify's officially recommended flow for frontend/SPA apps
 * - Uses a one-time cryptographic "code verifier" instead of a secret
 *
 * HOW IT WORKS (simplified):
 * 1. App generates a random code_verifier + its hashed version (code_challenge)
 * 2. User is redirected to Spotify login with the code_challenge
 * 3. Spotify redirects back with a short-lived ?code=... in the URL
 * 4. App exchanges that code + the original code_verifier for an access token
 *    (Spotify verifies the hash matches — no secret needed)
 *
 * SETUP:
 * 1. Go to https://developer.spotify.com/dashboard → Create app
 * 2. Add this page's URL as a Redirect URI (e.g. http://127.0.0.1:5500/index.html
 *    if using VS Code Live Server, or wherever you open the file)
 * 3. Paste your Client ID below — that's the only credential needed here
 */

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const CLIENT_ID    = 'YOUR_CLIENT_ID_HERE';   // ← paste your Client ID
const REDIRECT_URI = window.location.origin + window.location.pathname; // auto-detects current URL
const SCOPES       = 'user-read-private';     // minimal scope; albums are public data

// Storage keys
const KEY_TOKEN        = 'sf_access_token';
const KEY_EXPIRES_AT   = 'sf_expires_at';
const KEY_VERIFIER     = 'sf_code_verifier';

// ─── PUBLIC API ──────────────────────────────────────────────────────────────

/**
 * Returns a valid access token, or kicks off the PKCE login flow.
 * Call this before every API request.
 *
 * @returns {Promise<string>} Access token
 */
export async function getAccessToken() {
  // 1. Handle the redirect callback from Spotify
  const params = new URLSearchParams(window.location.search);
  const code   = params.get('code');
  const error  = params.get('error');

  if (error) {
    throw new Error(`Spotify login cancelled or denied: ${error}`);
  }

  if (code) {
    // We're back from Spotify — exchange the code for a token
    await exchangeCodeForToken(code);
    // Clean the URL so the code isn't reused on refresh
    window.history.replaceState({}, '', window.location.pathname);
  }

  // 2. Return cached token if still valid
  const token     = sessionStorage.getItem(KEY_TOKEN);
  const expiresAt = Number(sessionStorage.getItem(KEY_EXPIRES_AT) || 0);

  if (token && Date.now() < expiresAt - 60_000) {
    return token;
  }

  // 3. No valid token — redirect user to Spotify login
  await redirectToSpotifyLogin();

  // This line is never reached (redirect happens above), but satisfies linters
  return '';
}

/**
 * Check if a Client ID has been configured.
 * @returns {boolean}
 */
export function isConfigured() {
  return CLIENT_ID !== 'YOUR_CLIENT_ID_HERE' && CLIENT_ID.trim() !== '';
}

/**
 * Check if the user is currently logged in with a valid token.
 * @returns {boolean}
 */
export function isLoggedIn() {
  const token     = sessionStorage.getItem(KEY_TOKEN);
  const expiresAt = Number(sessionStorage.getItem(KEY_EXPIRES_AT) || 0);
  return !!token && Date.now() < expiresAt - 60_000;
}

/**
 * Clear the stored token, effectively logging the user out.
 */
export function logout() {
  sessionStorage.removeItem(KEY_TOKEN);
  sessionStorage.removeItem(KEY_EXPIRES_AT);
}

// ─── PKCE INTERNALS ──────────────────────────────────────────────────────────

/**
 * Step 1: Generate a random code verifier, hash it, and redirect to Spotify.
 */
async function redirectToSpotifyLogin() {
  const verifier  = generateVerifier(128);
  const challenge = await generateChallenge(verifier);

  // Store the verifier so we can use it after the redirect
  sessionStorage.setItem(KEY_VERIFIER, verifier);

  const authUrl = new URL('https://accounts.spotify.com/authorize');
  authUrl.searchParams.set('client_id',             CLIENT_ID);
  authUrl.searchParams.set('response_type',         'code');
  authUrl.searchParams.set('redirect_uri',          REDIRECT_URI);
  authUrl.searchParams.set('scope',                 SCOPES);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('code_challenge',        challenge);

  window.location.href = authUrl.toString();
}

/**
 * Step 2: Exchange the authorization code for an access token.
 * @param {string} code — from the ?code= URL param after Spotify redirect
 */
async function exchangeCodeForToken(code) {
  const verifier = sessionStorage.getItem(KEY_VERIFIER);

  if (!verifier) {
    throw new Error('PKCE verifier missing from session. Please try logging in again.');
  }

  const response = await fetch('https://accounts.spotify.com/api/token', {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     CLIENT_ID,
      grant_type:    'authorization_code',
      code,
      redirect_uri:  REDIRECT_URI,
      code_verifier: verifier,
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(`Token exchange failed: ${err.error_description || response.status}`);
  }

  const data = await response.json();

  sessionStorage.setItem(KEY_TOKEN,      data.access_token);
  sessionStorage.setItem(KEY_EXPIRES_AT, String(Date.now() + data.expires_in * 1000));
  sessionStorage.removeItem(KEY_VERIFIER); // verifier is single-use

  console.log('[Auth] PKCE token obtained, expires in', data.expires_in, 's');
}

// ─── CRYPTO HELPERS ──────────────────────────────────────────────────────────

/**
 * Generates a cryptographically random string of the given length.
 * Uses characters safe for URL encoding.
 */
function generateVerifier(length) {
  const chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const array  = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, byte => chars[byte % chars.length]).join('');
}

/**
 * SHA-256 hashes the verifier, then base64url-encodes it.
 * This is the code_challenge Spotify verifies against.
 */
async function generateChallenge(verifier) {
  const encoded = new TextEncoder().encode(verifier);
  const digest  = await crypto.subtle.digest('SHA-256', encoded);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, ''); // base64url (no padding)
}