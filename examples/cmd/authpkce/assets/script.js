// Global constants for easy tweaking
const AUTO_REFRESH_THRESHOLD_MS = 4 * 60 * 1000; // 4 minutes before expiry
const EXPIRY_TIMER_INTERVAL_MS = 1000;   // Timer update interval

// Utility for custom message boxes
function showMessageBox(message, title = 'Notification') {
  const overlay = document.createElement('div');
  overlay.className = 'message-box-overlay';
  overlay.innerHTML = `
    <div class="message-box-content">
      <p>${message}</p>
      <button onclick="this.closest('.message-box-overlay').remove()">OK</button>
    </div>
  `;
  document.body.appendChild(overlay);
}

// Show OAuth2 error from query params if present
(function() {
  const url = new URL(window.location.href);
  const error = url.searchParams.get('error');
  const errorDesc = url.searchParams.get('error_description');
  if (error) {
    const errorBox = document.createElement('div');
    errorBox.style.background = '#fed7d7';
    errorBox.style.color = '#c53030';
    errorBox.style.padding = '1em';
    errorBox.style.borderRadius = '0.5em';
    errorBox.style.marginBottom = '1.5em';
    errorBox.style.fontWeight = '600';
    errorBox.style.fontSize = '1.1em';
    errorBox.style.textAlign = 'center';
    errorBox.innerHTML = `<b>OAuth2 Error:</b> ${error}<br>${errorDesc ? `<span style='font-weight:400;'>${decodeURIComponent(errorDesc)}</span>` : ''}`;
    document.body.prepend(errorBox);
  }
})();

// PKCE OAuth2 Demo JS (injected config)
const config = {
  ...window.__APP_CONFIG__,
  redirectUri: window.location.origin + window.location.pathname,
};

// PKCE helpers
function base64urlencode(a) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(a)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function sha256(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await window.crypto.subtle.digest('SHA-256', buf);
  return base64urlencode(hash);
}

function randomString(len) {
  const arr = new Uint8Array(len);
  window.crypto.getRandomValues(arr);
  return Array.from(arr).map(x => ('0' + x.toString(16)).slice(-2)).join('');
}

// State
let codeVerifier = null;
let tokens = null;
let dpopKeyPair = null; // CryptoKeyPair object
let dpopPublicKeyJwk = null; // Public JWK for display and DPoP header

// UI Elements
const loginBtn = document.getElementById('login');
const logoutBtn = document.getElementById('logout');
const refreshTokenBtn = document.getElementById('refresh-token');
const loginStatus = document.getElementById('login-status');
const userinfoSection = document.getElementById('userinfo-section');
const fetchUserinfoBtn = document.getElementById('fetch-userinfo');
const userinfoPre = document.getElementById('userinfo-pre');
const endpointsSection = document.getElementById('endpoints-section');
const endpointBtns = document.querySelectorAll('.endpoint-btn');
const endpointResult = document.getElementById('endpoint-result');
const tokensPre = document.getElementById('tokens-pre');
const autoRefreshCheckbox = document.getElementById('auto-refresh-token');
const dpopKeysSection = document.getElementById('dpop-keys-section');
const dpopKeyInfoPre = document.getElementById('dpop-key-info-pre');

// --- Token Expiry Timer and Auto-Refresh ---
let expiryTimerInterval = null;
let autoRefreshEnabled = autoRefreshCheckbox.checked;
const tokenExpiryTimer = document.getElementById('token-expiry-timer');

function getAccessTokenExpiry() {
  if (!tokens || !tokens.access_token) return null;
  const at = parseJwt(tokens.access_token);
  if (!at.exp) return null;
  return at.exp * 1000; // exp is in seconds
}

function updateTokenExpiryTimer() {
  const expiry = getAccessTokenExpiry();
  if (!expiry) {
    tokenExpiryTimer.textContent = '';
    return;
  }
  const now = Date.now();
  let seconds = Math.max(0, Math.floor((expiry - now) / 1000));
  let min = Math.floor(seconds / 60);
  let sec = seconds % 60;
  tokenExpiryTimer.textContent = `Access token expires in: ${min}:${sec.toString().padStart(2, '0')}`;
}

function startExpiryTimer() {
  if (expiryTimerInterval) clearInterval(expiryTimerInterval);
  updateTokenExpiryTimer();
  expiryTimerInterval = setInterval(() => {
    updateTokenExpiryTimer();
    if (autoRefreshEnabled) {
      const expiry = getAccessTokenExpiry();
      // Auto-refresh if expiry is within the threshold and token is still valid
      if (expiry && expiry - Date.now() < AUTO_REFRESH_THRESHOLD_MS && expiry - Date.now() > 0) {
        refreshToken();
      }
    }
  }, EXPIRY_TIMER_INTERVAL_MS);
}

function stopExpiryTimer() {
  if (expiryTimerInterval) clearInterval(expiryTimerInterval);
  tokenExpiryTimer.textContent = '';
}

autoRefreshCheckbox.onchange = function() {
  autoRefreshEnabled = autoRefreshCheckbox.checked;
};

// Main UI update functions
function showTokens() {
  if (!tokens) {
    tokensPre.innerHTML = '';
    return;
  }
  // Prepare token values and decoded JWTs
  const accessToken = tokens.access_token || '';
  const idToken = tokens.id_token || '';
  const refreshToken = tokens.refresh_token || '';
  let accessJwt = '';
  let idJwt = '';
  try {
    accessJwt = accessToken ? JSON.stringify(parseJwt(accessToken), null, 2) : 'Not a JWT or empty';
  } catch (e) {
    accessJwt = 'Invalid JWT: ' + e.message;
  }
  try {
    idJwt = idToken ? JSON.stringify(parseJwt(idToken), null, 2) : 'Not a JWT or empty';
  } catch (e) {
    idJwt = 'Invalid JWT: ' + e.message;
  }
  // Layout: 3 columns for easy comparison
  tokensPre.innerHTML = `
    <div class="flex gap-4 flex-wrap">
      <div class="flex-1 min-w-[250px]">
        <b class="text-lg">Access Token</b>
        <pre class="token">${accessToken}</pre>
        <details open><summary class="font-medium cursor-pointer text-blue-700">Decoded JWT</summary><pre>${accessJwt}</pre></details>
      </div>
      <div class="flex-1 min-w-[250px]">
        <b class="text-lg">ID Token</b>
        <pre class="token">${idToken}</pre>
        <details open><summary class="font-medium cursor-pointer text-blue-700">Decoded JWT</summary><pre>${idJwt}</pre></details>
      </div>
      <div class="flex-1 min-w-[250px]">
        <b class="text-lg">Refresh Token</b>
        <pre class="token">${refreshToken}</pre>
      </div>
    </div>
  `;
  startExpiryTimer();
}

// Helper to decode JWT
function parseJwt(token) {
  if (!token) throw new Error("Token is empty");
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error("Invalid JWT format (expected 3 parts)");
  const base64Url = parts[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  // Pad base64 string to be a multiple of 4
  const paddedBase64 = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  const jsonPayload = decodeURIComponent(atob(paddedBase64).split('').map(function(c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));
  return JSON.parse(jsonPayload);
}

function showUserInfo() {
  let html = '';
  if (tokens && tokens.id_token) {
    const idt = parseJwt(tokens.id_token);
    if (idt.email) html += ` | <b>Email:</b> ${idt.email}`;
    if (idt.preferred_username) html += ` | <b>User:</b> ${idt.preferred_username}`;
  }
  if (tokens && tokens.access_token) {
    const at = parseJwt(tokens.access_token);
    if (at.sub) html += ` | <b>Sub:</b> ${at.sub}`;
  }
  document.getElementById('user-info').innerHTML = html;
}

function setLoggedIn(loggedIn) {
  loginBtn.style.display = loggedIn ? 'none' : '';
  logoutBtn.style.display = loggedIn ? '' : 'none';
  refreshTokenBtn.style.display = loggedIn ? '' : 'none';
  loginStatus.textContent = loggedIn ? 'Logged in' : 'Not logged in';
  loginStatus.className = `status-text ${loggedIn ? 'success-text' : 'error-text'}`;

  tokenExpiryTimer.style.display = loggedIn ? '' : 'none';
  autoRefreshCheckbox.parentElement.style.display = loggedIn ? '' : 'none';
  userinfoSection.style.display = loggedIn ? '' : 'none';
  endpointsSection.style.display = loggedIn ? '' : 'none';
  dpopKeysSection.style.display = useDpop && loggedIn ? '' : 'none'; // Show DPoP keys only if DPoP is enabled and logged in

  showTokens();
  showUserInfo();
  if (loggedIn) {
    startExpiryTimer();
    if (useDpop && dpopPublicKeyJwk) {
      dpopKeyInfoPre.textContent = JSON.stringify(dpopPublicKeyJwk, null, 2);
    } else {
      dpopKeyInfoPre.textContent = 'DPoP not enabled or key not generated.';
    }
  } else {
    stopExpiryTimer();
    dpopKeyInfoPre.textContent = '';
  }
}

function clearTokens() {
  tokens = null;
  localStorage.removeItem('pkce_tokens');
  localStorage.removeItem('pkce_code_verifier');
  // Do NOT remove DPoP keys here, as they persist across sessions for the client.
  // localStorage.removeItem('pkce_dpop_priv');
  // localStorage.removeItem('pkce_dpop_pub');
  dpopKeyPair = null; // Clear in-memory key pair
  dpopPublicKeyJwk = null; // Clear in-memory public JWK
  showTokens();
  stopExpiryTimer();
}

function saveTokens(t) {
  tokens = t;
  localStorage.setItem('pkce_tokens', JSON.stringify(tokens));
  showTokens();
}

function loadTokens() {
  const t = localStorage.getItem('pkce_tokens');
  if (t) tokens = JSON.parse(t);
  showTokens();
}

// DPoP support
let useDpop = false;
const withDpopCheckbox = document.getElementById('with-dpop');
if (withDpopCheckbox) {
  withDpopCheckbox.onchange = async function() {
    useDpop = withDpopCheckbox.checked;
    localStorage.setItem('pkce_with_dpop', useDpop ? '1' : '0');
    if (useDpop && !dpopKeyPair) {
      await initializeDpopKeyPair();
    }
    setLoggedIn(!!tokens && !!tokens.access_token); // Update UI based on DPoP state
  };
}

async function generateDpopKeyPair() {
  // Use ECDSA P-256 for DPoP as recommended by RFC 9449
  const keyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // extractable
    ['sign', 'verify']
  );
  const privJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const pubJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
  // Ensure alg and use are set for JWK
  pubJwk.alg = 'ES256';
  pubJwk.use = 'sig';

  localStorage.setItem('pkce_dpop_priv', JSON.stringify(privJwk));
  localStorage.setItem('pkce_dpop_pub', JSON.stringify(pubJwk));
  dpopKeyPair = keyPair;
  dpopPublicKeyJwk = pubJwk;
  return keyPair;
}

async function restoreDpopKeyPair() {
  if (dpopKeyPair) return dpopKeyPair; // Already restored
  const privStr = localStorage.getItem('pkce_dpop_priv');
  const pubStr = localStorage.getItem('pkce_dpop_pub');
  if (privStr && pubStr) {
    try {
      const privJwk = JSON.parse(privStr);
      const pubJwk = JSON.parse(pubStr);
      const privateKey = await window.crypto.subtle.importKey('jwk', privJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
      const publicKey = await window.crypto.subtle.importKey('jwk', pubJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
      dpopKeyPair = { privateKey, publicKey };
      dpopPublicKeyJwk = pubJwk; // Store for display
      return dpopKeyPair;
    } catch (e) {
      console.error("Failed to restore DPoP key pair:", e);
      localStorage.removeItem('pkce_dpop_priv'); // Clear corrupted keys
      localStorage.removeItem('pkce_dpop_pub');
      dpopKeyPair = null;
      dpopPublicKeyJwk = null;
      return null;
    }
  }
  return null;
}

async function initializeDpopKeyPair() {
  await restoreDpopKeyPair();
  if (!dpopKeyPair) {
    await generateDpopKeyPair();
  }
  if (useDpop && dpopPublicKeyJwk) {
    dpopKeyInfoPre.textContent = JSON.stringify(dpopPublicKeyJwk, null, 2);
  } else {
    dpopKeyInfoPre.textContent = 'DPoP not enabled or key not generated.';
  }
}

// --- DPoP signing helpers ---
async function sha256B64(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await window.crypto.subtle.digest('SHA-256', buf);
  return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signDpopJwt({ htm, htu, accessToken, jwk, keyPair }) {
  // Minimal DPoP JWT implementation for demo
  const header = {
    alg: 'ES256', // Algorithm must match key type
    typ: 'dpop+jwt',
    jwk: jwk
  };
  const iat = Math.floor(Date.now() / 1000); // Issued At timestamp
  const payload = {
    htm, // HTTP Method
    htu, // HTTP URL
    iat,
    jti: randomString(32), // JWT ID for replay protection
    ...(accessToken ? { ath: await sha256B64(accessToken) } : {}) // Access Token Hash
  };

  function base64url(obj) {
    return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  const toSign = base64url(header) + '.' + base64url(payload);
  const enc = new TextEncoder().encode(toSign);
  const sig = await window.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, enc);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return toSign + '.' + sigB64;
}

// --- STATE PARAMETER HANDLING FOR OAUTH2 ---
function generateState() {
  return randomString(32);
}

function saveState(state) {
  sessionStorage.setItem('pkce_state', state);
}

function loadState() {
  return sessionStorage.getItem('pkce_state');
}

function clearState() {
  sessionStorage.removeItem('pkce_state');
}

// Login function
async function login() {
  codeVerifier = randomString(64);
  localStorage.setItem('pkce_code_verifier', codeVerifier);
  const codeChallenge = await sha256(codeVerifier);

  // --- STATE PARAMETER ---
  const state = generateState();
  saveState(state);

  localStorage.setItem('pkce_with_dpop', useDpop ? '1' : '0');
  if (useDpop) {
    await initializeDpopKeyPair();
    if (!dpopKeyPair) {
      showMessageBox('Failed to generate or restore DPoP key pair. Please try again.');
      return;
    }
  }

  const params = [
    'response_type=code',
    'client_id=' + encodeURIComponent(config.clientId),
    'redirect_uri=' + encodeURIComponent(config.redirectUri),
    'scope=' + encodeURIComponent(config.scope),
    'code_challenge=' + encodeURIComponent(codeChallenge),
    'code_challenge_method=S256',
    'state=' + encodeURIComponent(state)
  ].join('&');
  window.location = config.authUrl + '?' + params;
}

// Handle redirect from OAuth2 server
async function handleRedirect() {
  const url = new URL(window.location.href);
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');
  if (!code) return false;

  // --- STATE PARAMETER CHECK ---
  const expectedState = loadState();
  clearState(); // Always clear after use
  if (!returnedState || !expectedState || returnedState !== expectedState) {
    showMessageBox('OAuth2 state mismatch or missing. Please try logging in again.');
    return false;
  }

  codeVerifier = localStorage.getItem('pkce_code_verifier');
  if (!codeVerifier) {
    showMessageBox('Code verifier not found. Please log in again.');
    return false;
  }

  const body = [
    'grant_type=authorization_code',
    'client_id=' + encodeURIComponent(config.clientId),
    'code_verifier=' + encodeURIComponent(codeVerifier),
    'code=' + encodeURIComponent(code),
    'redirect_uri=' + encodeURIComponent(config.redirectUri)
  ].join('&');

  const opts = {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  };

  // DPoP header for token endpoint
  if (useDpop) {
    await restoreDpopKeyPair();
    if (!dpopKeyPair || !dpopPublicKeyJwk) {
      showMessageBox('DPoP key missing after redirect. Please log in again with DPoP enabled.');
      return false;
    }
    // Always use the canonical URL for the token endpoint as htu
    const htu = config.tokenUrl;
    opts.headers['DPoP'] = await signDpopJwt({ htm: 'POST', htu, jwk: dpopPublicKeyJwk, keyPair: dpopKeyPair });
  }

  try {
    const resp = await fetch(config.tokenUrl, opts);
    const data = await resp.json();

    if (data.access_token) {
      saveTokens(data);
      window.history.replaceState({}, '', config.redirectUri);
      setLoggedIn(true);
    } else {
      showMessageBox('Token exchange failed: ' + JSON.stringify(data, null, 2));
      console.error('Token exchange failed:', data);
    }
  } catch (e) {
    showMessageBox('Token exchange error: ' + e.message);
    console.error('Token exchange error:', e);
  }
  return true;
}

async function fetchUserinfo() {
  if (!tokens || !tokens.access_token) {
    showMessageBox('No access token available.');
    return;
  }
  userinfoPre.textContent = 'Loading UserInfo...';

  // Helper to actually make the request
  async function doRequest(useDpopHeader, forceBearerAuthPrefix = false, overrideHtu = null) {
    let headers = {};
    let url = config.userinfoUrl;
    if (useDpopHeader) {
      await restoreDpopKeyPair();
      if (!dpopKeyPair || !dpopPublicKeyJwk) {
        showMessageBox('DPoP key missing. Please log in again with DPoP enabled.');
        userinfoPre.textContent = '<span class="error-text">DPoP key missing.</span>';
        return { error: true };
      }
      // If forceBearerAuthPrefix, use 'Bearer' instead of 'DPoP' for the Authorization header
      headers['Authorization'] = (forceBearerAuthPrefix ? 'Bearer ' : 'DPoP ') + tokens.access_token;
      // Use overrideHtu if provided, else default
      const htu = overrideHtu || url;
      headers['DPoP'] = await signDpopJwt({ htm: 'GET', htu, accessToken: tokens.access_token, jwk: dpopPublicKeyJwk, keyPair: dpopKeyPair });
    } else {
      headers['Authorization'] = 'Bearer ' + tokens.access_token;
    }

    try {
      const resp = await fetch(url, { headers });
      // Try to parse JSON, but fallback to empty object if not JSON
      let data = {};
      try {
        data = await resp.json();
      } catch {}
      return { resp, data };
    } catch (e) {
      userinfoPre.textContent = `Error fetching UserInfo: ${e.message}`;
      console.error('Error fetching UserInfo:', e);
      return { error: true };
    }
  }

  // First attempt: use current mode (useDpop)
  let { resp, data, error } = await doRequest(useDpop);
  if (error) return;

  if (resp.ok) {
    userinfoPre.textContent = JSON.stringify(data, null, 2);
    return;
  }

  // Check WWW-Authenticate header for fallback logic
  const wwwAuth = resp.headers.get('WWW-Authenticate') || '';
  const sentDpop = useDpop;
  const sentBearer = !useDpop;
  // Only check for 'Bearer' (case-insensitive) in the header name
  const wantsDpop = /DPoP proof/.test(wwwAuth) || /DPoP/i.test(wwwAuth);
  const wantsBearer = /bearer/i.test(wwwAuth);

  // Check for incorrect htu claim error in response body
  let htuErrorMatch = null;
  if (data && typeof data.message === 'string') {
    htuErrorMatch = data.message.match(/incorrect `htu` claim.*should match \[\[(.*?)\]\]/);
  }
  if (htuErrorMatch) {
    // Try all allowed htu values in order until one works
    const allowedHtuList = htuErrorMatch[1].split(' ').map(u => {
      // If it starts with '/', use as-is (path only)
      if (u.startsWith('/')) return window.location.origin + u;
      try {
        // If it's a full URL, use as-is
        new URL(u); // will throw if not a valid URL
        return u;
      } catch {
        // If not a valid URL, try to prepend origin
        if (u) return window.location.origin + u;
        return u;
      }
    });
    for (const allowedHtu of allowedHtuList) {
      let retry = await doRequest(true, forceBearerAuthPrefix, allowedHtu);
      if (retry.error) return;
      if (retry.resp.ok) {
        userinfoPre.textContent = JSON.stringify(retry.data, null, 2);
        return;
      }
    }
    // If none worked, show the last error
    userinfoPre.textContent = `Error fetching UserInfo: ${resp.status} ${resp.statusText}\n${JSON.stringify(data, null, 2)}`;
    console.error('Error fetching UserInfo:', data);
    return;
  }

  if (wantsDpop && sentBearer) {
    userinfoPre.innerHTML = `<span class="error-text">DPoP is required for this endpoint. Please enable DPoP and try again.</span>`;
    showMessageBox('DPoP is required for this endpoint. Please enable DPoP and try again.');
    return;
  }

  if (wantsBearer && sentDpop) {
    // Retry with Bearer prefix but still send DPoP proof
    let retry = await doRequest(true, true);
    if (retry.error) return;
    if (retry.resp.ok) {
      userinfoPre.textContent = JSON.stringify(retry.data, null, 2);
    } else {
      userinfoPre.textContent = `Error fetching UserInfo: ${retry.resp.status} ${retry.resp.statusText}\n${JSON.stringify(retry.data, null, 2)}`;
      console.error('Error fetching UserInfo:', retry.data);
    }
    return;
  }

  // Default: show error as before
  userinfoPre.textContent = `Error fetching UserInfo: ${resp.status} ${resp.statusText}\n${JSON.stringify(data, null, 2)}`;
  console.error('Error fetching UserInfo:', data);
}

async function refreshToken() {
  if (!tokens || !tokens.refresh_token) {
    showMessageBox('No refresh token available.');
    return;
  }

  let expired = false;
  try {
    const parts = tokens.refresh_token.split('.');
    if (parts.length === 3) {
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        expired = true;
      }
    }
  } catch (e) {
    // Ignore parse errors, assume not a JWT or not expired
  }
  if (expired) {
    clearTokens();
    setLoggedIn(false);
    showMessageBox('Your refresh token has expired. Please log in again.');
    return;
  }

  const body = [
    'grant_type=refresh_token',
    'client_id=' + encodeURIComponent(config.clientId),
    'refresh_token=' + encodeURIComponent(tokens.refresh_token)
  ].join('&');

  const opts = {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  };

  // DPoP header for token endpoint (refresh token grant)
  if (useDpop) {
    await restoreDpopKeyPair();
    if (!dpopKeyPair || !dpopPublicKeyJwk) {
      showMessageBox('DPoP key missing. Please log in again with DPoP enabled.');
      return;
    }
    const htu = new URL(config.tokenUrl).toString(); // Canonical URL for token endpoint
    opts.headers['DPoP'] = await signDpopJwt({ htm: 'POST', htu, jwk: dpopPublicKeyJwk, keyPair: dpopKeyPair });
  }

  try {
    const resp = await fetch(config.tokenUrl, opts);
    const data = await resp.json();

    if (data.access_token) {
      // Preserve the old refresh token if not returned (Keycloak often doesn't rotate refresh tokens)
      if (!data.refresh_token && tokens.refresh_token) {
        data.refresh_token = tokens.refresh_token;
      }
      saveTokens(data);
      setLoggedIn(true);
    } else {
      // If error is invalid_grant or similar, treat as expired
      if (data.error === 'invalid_grant' || (data.error_description && data.error_description.toLowerCase().includes('expired'))) {
        clearTokens();
        setLoggedIn(false);
        showMessageBox('Your session has expired. Please log in again.');
      } else {
        showMessageBox('Token refresh failed: ' + JSON.stringify(data, null, 2));
        console.error('Token refresh failed:', data);
      }
    }
  } catch (e) {
    showMessageBox('Token refresh error: ' + e.message);
    console.error('Token refresh error:', e);
  }
}

async function logout() {
  // Save id_token before clearing tokens
  var idTokenHint = tokens && tokens.id_token ? tokens.id_token : null;
  clearTokens();
  setLoggedIn(false);
  stopExpiryTimer();
  // Open logout in a new window/tab with post_logout_redirect_uri and id_token_hint to return to index
  let logoutUrl = config.logoutUrl;
  const params = [];
  const redirectUri = encodeURIComponent(config.redirectUri);
  params.push('post_logout_redirect_uri=' + redirectUri);
  if (idTokenHint) {
    params.push('id_token_hint=' + encodeURIComponent(idTokenHint));
  }
  logoutUrl += (logoutUrl.includes('?') ? '&' : '?') + params.join('&');
  window.open(logoutUrl, '_blank', 'noopener,noreferrer,width=500,height=600');
  endpointResult.textContent = ''; // Clear endpoint result
}

async function callEndpoint(url, method) {
  const btn = Array.from(document.querySelectorAll('.endpoint-btn')).find(b => b.getAttribute('data-url') === url);
  let body = '{}';
  if (btn && btn.hasAttribute('data-body')) {
    body = btn.getAttribute('data-body');
  }
  endpointResult.innerHTML = '<em>Loading...</em>';

  const fetchOptions = {
    method: method,
    headers: {}
  };

  if (tokens && tokens.access_token) {
    if (useDpop) {
      await restoreDpopKeyPair();
      if (!dpopKeyPair || !dpopPublicKeyJwk) {
        endpointResult.innerHTML = '<span class="error-text">DPoP key missing. Please log in again with DPoP enabled.</span>';
        showMessageBox('DPoP key missing. Please log in again with DPoP enabled.');
        return;
      }
      fetchOptions.headers['Authorization'] = 'DPoP ' + tokens.access_token;
      // Use only the path for htu if backend expects /path (see error message)
      const htu = new URL(url, window.location.origin).pathname;
      fetchOptions.headers['DPoP'] = await signDpopJwt({ htm: method, htu, accessToken: tokens.access_token, jwk: dpopPublicKeyJwk, keyPair: dpopKeyPair });
    } else {
      fetchOptions.headers['Authorization'] = 'Bearer ' + tokens.access_token;
    }
  }

  if (method === 'POST') {
    fetchOptions.body = body;
    fetchOptions.headers['Content-Type'] = 'application/json';
  }

  // Render request (with styling)
  let reqLines = [];
  reqLines.push(`<b>${method} <span style='word-break:break-all;'>${url}</span></b>`);
  reqLines.push('<div style="height:0.5em;"></div>'); // Add space before headers
  Object.entries(fetchOptions.headers).forEach(([k, v]) => {
    if (v) reqLines.push(`<span class='header-key'>${k}:</span> <span class='header-value'>${v}</span>`);
  });
  if (fetchOptions.body && fetchOptions.body.trim() !== '{}') {
    reqLines.push('<br>');
    try {
      reqLines.push(`<pre class='request-response-box pre'>${JSON.stringify(JSON.parse(fetchOptions.body), null, 2)}</pre>`);
    } catch {
      reqLines.push(`<pre class='request-response-box pre'>${fetchOptions.body}</pre>`);
    }
  }

  fetch(url, fetchOptions)
    .then(async response => {
      let respLines = [];
      respLines.push(`<b>${response.status} ${response.statusText}</b>`);
      response.headers.forEach((v, k) => {
        respLines.push(`<span class='header-key'>${k}:</span> <span class='header-value'>${v}</span>`);
      });
      let text = await response.text();
      if (text) {
        respLines.push('<br>');
        try {
          respLines.push(`<pre class='request-response-box pre'>${JSON.stringify(JSON.parse(text), null, 2)}</pre>`);
        } catch {
          respLines.push(`<pre class='request-response-box pre'>${text}</pre>`);
        }
      }
      endpointResult.innerHTML = `
        <div class='request-response-container'>
          <div class='request-response-box'>
            <b class='text-lg'>Request</b>
            <div class='mt-2'>${reqLines.join('<br>')}</div>
          </div>
          <div class='request-response-box'>
            <b class='text-lg'>Response</b>
            <div class='mt-2'>${respLines.join('<br>')}</div>
          </div>
        </div>
      `;
    })
    .catch(error => {
      endpointResult.innerHTML = `
        <div class='request-response-container'>
          <div class='request-response-box'>
            <b class='text-lg'>Request</b>
            <div class='mt-2'>${reqLines.join('<br>')}</div>
          </div>
          <div class='request-response-box'>
            <b class='text-lg'>Response</b>
            <div class='mt-2 error-text'>Error: ${error}</div>
          </div>
        </div>
      `;
    });
}

// Event listeners
loginBtn.onclick = login;
logoutBtn.onclick = logout;
fetchUserinfoBtn.onclick = fetchUserinfo;
refreshTokenBtn.onclick = refreshToken;
endpointBtns.forEach(btn => {
  btn.onclick = () => callEndpoint(btn.getAttribute('data-url'), btn.getAttribute('data-method'));
});

// Patch endpoint button URLs at runtime
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.endpoint-btn').forEach(btn => {
    btn.setAttribute('data-url', btn.getAttribute('data-url').replace('__PLATFORM_ENDPOINT__', config.platformEndpoint));
  });
});

// Init
(async function() {
  // Restore DPoP preference before any logic
  useDpop = localStorage.getItem('pkce_with_dpop') === '1';
  if (withDpopCheckbox) withDpopCheckbox.checked = useDpop;

  // Initialize DPoP key pair if DPoP is enabled
  if (useDpop) {
    await initializeDpopKeyPair();
  }

  loadTokens();
  if (await handleRedirect()) return; // If redirect handled, stop further init
  setLoggedIn(!!tokens && !!tokens.access_token);
})();