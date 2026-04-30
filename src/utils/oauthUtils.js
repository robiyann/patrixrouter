/**
 * oauthUtils.js
 *
 * Full OAuth Login Flow untuk mendapatkan refresh_token, access_token, id_token
 * dari ChatGPT/OpenAI menggunakan Codex Desktop client credentials.
 *
 * Diimplementasikan berdasarkan referensi: /Users/krisnaar/Downloads/Gplus Token/main.go
 *
 * Flow:
 *  1. Build PKCE + authorize URL
 *  2. Follow authorize redirects → landing di login page
 *  3. POST /api/accounts/authorize/continue  (kirim email)
 *  4. POST /api/accounts/password/verify     (kirim password) → dapat login_verifier / continue_url
 *  5. Handle OTP jika continue_url berisi "email-verification"
 *  6. POST /api/accounts/workspace/select   (workspace_id: "personal") → dapat login_verifier final
 *  7. Build consent URL dengan login_verifier, follow redirect chain → auth code
 *  8. POST /oauth/token                      (tukar auth code → RT, AT, IDT)
 */

const crypto = require("crypto");
const logger = require("./logger");

// ============================================================
// Constants  (Codex Desktop)
// ============================================================
const CLIENT_ID   = "app_EMoamEEZ73f0CkXaXp7hrann";
const REDIRECT_URI = "http://localhost:1455/auth/callback";
const SCOPE        = "openid profile email offline_access api.connectors.read api.connectors.invoke";
const ORIGINATOR   = "Codex Desktop";
const AUTH_BASE    = "https://auth.openai.com";
const TOKEN_URL    = `${AUTH_BASE}/oauth/token`;

const DEFAULT_UA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";

// ============================================================
// PKCE helpers
// ============================================================
function b64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function generatePKCE() {
  const verifier  = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

function generateState() {
  return b64url(crypto.randomBytes(16));
}

// ============================================================
// Cookie Jar (simple, domain-based)
// ============================================================
class CookieJar {
  constructor() { this._store = {}; }

  capture(headers, urlStr) {
    if (!headers) return;
    let setCookie = headers["Set-Cookie"] || headers["set-cookie"] || [];
    if (!Array.isArray(setCookie)) setCookie = [setCookie];
    for (const raw of setCookie) {
      if (!raw) continue;
      const m = raw.match(/^([^=]+)=([^;]*)/);
      if (!m) continue;
      const name = m[1].trim();
      const value = m[2];
      // Try to extract domain from cookie
      const dm = raw.match(/[Dd]omain=\.?([^;,\s]+)/);
      let domain;
      try {
        domain = dm ? dm[1].toLowerCase() : new URL(urlStr).hostname;
      } catch { domain = "auth.openai.com"; }
      if (!this._store[domain]) this._store[domain] = {};
      this._store[domain][name] = value;
    }
  }

  headerFor(urlStr) {
    let hostname;
    try { hostname = new URL(urlStr).hostname; } catch { return undefined; }
    const parts = [];
    for (const [domain, cookies] of Object.entries(this._store)) {
      if (hostname === domain || hostname.endsWith("." + domain)) {
        for (const [k, v] of Object.entries(cookies)) {
          parts.push(`${k}=${v}`);
        }
      }
    }
    return parts.length ? parts.join("; ") : undefined;
  }
}

// ============================================================
// CycleTLS request helpers
// ============================================================
async function tlsGet(cycleTLS, url, jar, ua, extraHeaders, proxy) {
  const cookie = jar.headerFor(url);
  const resp = await cycleTLS(url, {
    headers: {
      "User-Agent": ua,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "sec-fetch-dest": "document",
      "sec-fetch-mode": "navigate",
      "sec-fetch-site": "cross-site",
      ...(cookie ? { Cookie: cookie } : {}),
      ...(extraHeaders || {}),
    },
    proxy: proxy || undefined,
    disableRedirect: true,
    timeout: 30,
  }, "get");
  jar.capture(resp.headers, url);
  return resp;
}

async function tlsPost(cycleTLS, url, bodyObj, jar, ua, referer, proxy) {
  const cookie = jar.headerFor(url);
  const bodyStr = JSON.stringify(bodyObj);
  const resp = await cycleTLS(url, {
    body: bodyStr,
    headers: {
      "User-Agent": ua,
      "Content-Type": "application/json",
      "Accept": "application/json",
      "Accept-Language": "en-US,en;q=0.9",
      "Origin": AUTH_BASE,
      "Referer": referer || `${AUTH_BASE}/`,
      "sec-fetch-dest": "empty",
      "sec-fetch-mode": "cors",
      "sec-fetch-site": "same-origin",
      ...(cookie ? { Cookie: cookie } : {}),
    },
    proxy: proxy || undefined,
    disableRedirect: false,
    timeout: 30,
  }, "post");
  jar.capture(resp.headers, url);
  return resp;
}

function parseJson(resp) {
  if (!resp || !resp.body) return {};
  try {
    return typeof resp.body === "string" ? JSON.parse(resp.body) : resp.body;
  } catch {
    try {
      return typeof resp.data === "string" ? JSON.parse(resp.data) : (resp.data || {});
    } catch { return {}; }
  }
}

// ============================================================
// Step 2: Follow authorize redirects to login page
// ============================================================
async function followRedirects(cycleTLS, startUrl, jar, ua, proxy, maxHops = 10) {
  let current = startUrl;
  for (let i = 0; i < maxHops; i++) {
    const resp = await tlsGet(cycleTLS, current, jar, ua, {
      "sec-fetch-site": i === 0 ? "cross-site" : "same-origin",
      Referer: i === 0 ? "https://chatgpt.com/" : AUTH_BASE + "/",
    }, proxy);

    if (resp.status === 0) throw new Error(`Network error on: ${current}`);

    let loc = resp.headers?.Location || resp.headers?.location;
    if (Array.isArray(loc)) loc = loc[0];
    if (resp.status >= 300 && resp.status < 400 && loc) {
      current = loc.startsWith("http") ? loc : new URL(loc, current).href;
      continue;
    }
    // 200 means we've landed
    return current;
  }
  throw new Error("Too many redirects in followRedirects");
}

// ============================================================
// Step 2b: Load the login page (to set cookies)
// ============================================================
async function loadPage(cycleTLS, url, jar, ua, referer, proxy) {
  const resp = await tlsGet(cycleTLS, url, jar, ua, {
    Referer: referer || AUTH_BASE + "/",
    "sec-fetch-site": "same-origin",
  }, proxy);
  jar.capture(resp.headers, url);
  return resp;
}

// ============================================================
// Step 3: POST /api/accounts/authorize/continue  (submit email)
// ============================================================
async function authorizeContinue(cycleTLS, email, jar, ua, proxy) {
  const url = `${AUTH_BASE}/api/accounts/authorize/continue`;
  const payload = { username: { kind: "email", value: email } };
  const resp = await tlsPost(cycleTLS, url, payload, jar, ua,
    `${AUTH_BASE}/log-in-or-create-account`, proxy);

  const data = parseJson(resp);
  if (resp.status !== 200) {
    throw new Error(`authorize/continue failed (${resp.status}): ${JSON.stringify(data)}`);
  }
  return data; // { continue_url? }
}

// ============================================================
// Step 4: POST /api/accounts/password/verify  (submit password)
// Returns { login_verifier?, continue_url? }
// ============================================================
async function passwordVerify(cycleTLS, password, jar, ua, proxy) {
  const url = `${AUTH_BASE}/api/accounts/password/verify`;
  const payload = { password };
  const resp = await tlsPost(cycleTLS, url, payload, jar, ua,
    `${AUTH_BASE}/log-in/password`, proxy);

  const data = parseJson(resp);
  if (resp.status === 401) throw new Error("401 wrong password");
  if (resp.status !== 200) {
    throw new Error(`password/verify failed (${resp.status}): ${JSON.stringify(data)}`);
  }
  return data; // { login_verifier?, continue_url? }
}

// ============================================================
// Step 4b (optional): Send OTP
// ============================================================
async function sendOTP(cycleTLS, jar, ua, proxy) {
  const url = `${AUTH_BASE}/api/accounts/passwordless/send-otp`;
  const resp = await tlsPost(cycleTLS, url, {}, jar, ua,
    `${AUTH_BASE}/log-in/password`, proxy);
  return parseJson(resp);
}

// ============================================================
// Step 4c: Validate OTP → returns login_verifier
// ============================================================
async function validateOTP(cycleTLS, code, jar, ua, proxy) {
  const url = `${AUTH_BASE}/api/accounts/email-otp/validate`;
  const payload = { code: code.toString() };
  const resp = await tlsPost(cycleTLS, url, payload, jar, ua,
    `${AUTH_BASE}/email-verification`, proxy);

  const data = parseJson(resp);
  if (resp.status !== 200) {
    throw new Error(`email-otp/validate failed (${resp.status}): ${JSON.stringify(data)}`);
  }
  return data?.login_verifier || data?.loginVerifier || "";
}

// ============================================================
// Step 6: POST /api/accounts/workspace/select
// ============================================================
async function workspaceSelect(cycleTLS, workspaceId, jar, ua, proxy, referer) {
  const url = `${AUTH_BASE}/api/accounts/workspace/select`;
  const payload = { workspace_id: workspaceId };
  const resp = await tlsPost(cycleTLS, url, payload, jar, ua,
    referer || `${AUTH_BASE}/`, proxy);

  const data = parseJson(resp);
  if (resp.status !== 200) {
    throw new Error(`workspace/select failed (${resp.status}): ${JSON.stringify(data)}`);
  }
  return data; // { login_verifier?, continue_url? }
}

// ============================================================
// Step 7: Follow consent chain → extract auth code
// ============================================================
async function followToAuthCode(cycleTLS, startUrl, jar, ua, proxy, maxHops = 15) {
  let current = startUrl;
  for (let i = 0; i < maxHops; i++) {
    // Check if we've already arrived at the callback
    if (current.includes("localhost:1455")) {
      return new URL(current).searchParams.get("code");
    }

    const resp = await tlsGet(cycleTLS, current, jar, ua, {
      Referer: current.includes("auth.openai.com") ? `${AUTH_BASE}/` : "https://chatgpt.com/",
      "sec-fetch-site": current.includes("auth.openai.com") ? "same-origin" : "cross-site",
    }, proxy);

    if (resp.status === 0) throw new Error(`Network error on consent redirect: ${current}`);

    let loc = resp.headers?.Location || resp.headers?.location;
    if (Array.isArray(loc)) loc = loc[0];

    // Check callback in location header
    if (loc && loc.includes("localhost:1455")) {
      const code = new URL(loc.startsWith("http") ? loc : new URL(loc, current).href).searchParams.get("code");
      if (code) return code;
    }

    if (resp.status >= 300 && resp.status < 400 && loc) {
      current = loc.startsWith("http") ? loc : new URL(loc, current).href;
      continue;
    }

    // 200 with no redirect — might be an error page
    throw new Error(`Got HTTP 200 at ${current.substring(0, 80)} (expected redirect to auth code)`);
  }
  throw new Error("Too many hops in followToAuthCode — auth code not found");
}

// ============================================================
// Step 8: Exchange auth code for tokens
// ============================================================
async function exchangeToken(cycleTLS, code, verifier, ua, proxy) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  }).toString();

  const resp = await cycleTLS(TOKEN_URL, {
    body,
    headers: {
      "User-Agent": ua,
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    },
    proxy: proxy || undefined,
    timeout: 30,
  }, "post");

  const data = parseJson(resp);
  if (resp.status !== 200) {
    throw new Error(`Token exchange failed (${resp.status}): ${JSON.stringify(data)}`);
  }
  if (!data.refresh_token) {
    throw new Error(`No refresh_token in response: ${JSON.stringify(data)}`);
  }
  return data;
}

// ============================================================
// Main export: performLoginOAuth
// ============================================================
async function performLoginOAuth(cycleTLS, email, password, proxyUrl, userAgent, fingerprint, otpFn) {
  if (!cycleTLS) throw new Error("cycleTLS instance is required");
  if (!email || !password) throw new Error("email and password are required");

  const ua = userAgent || DEFAULT_UA;
  const proxy = proxyUrl || undefined;
  const jar = new CookieJar();

  // Step 1: PKCE + state
  const { verifier, challenge } = generatePKCE();
  const state = generateState();

  logger.info(`[OAuth] Starting login flow for ${email}`);

  // Step 2: Build authorize URL and follow to login page
  const authorizeParams = new URLSearchParams({
    client_id: CLIENT_ID,
    code_challenge: challenge,
    code_challenge_method: "S256",
    codex_cli_simplified_flow: "true",
    id_token_add_organizations: "true",
    originator: ORIGINATOR,
    prompt: "login",
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: SCOPE,
    state,
  });
  const authorizeUrl = `${AUTH_BASE}/oauth/authorize?${authorizeParams.toString()}`;

  const loginPageUrl = await followRedirects(cycleTLS, authorizeUrl, jar, ua, proxy);
  logger.info(`[OAuth] Landed on: ${loginPageUrl.substring(0, 60)}`);

  // Load the login page (sets cookies)
  await loadPage(cycleTLS, loginPageUrl, jar, ua, "https://chatgpt.com/", proxy);

  // Step 3: Submit email
  logger.info(`[OAuth] Submitting email...`);
  const continueData = await authorizeContinue(cycleTLS, email, jar, ua, proxy);
  // Follow continue_url if provided
  if (continueData.continue_url) {
    const cu = continueData.continue_url.startsWith("http")
      ? continueData.continue_url
      : AUTH_BASE + continueData.continue_url;
    await loadPage(cycleTLS, cu, jar, ua, `${AUTH_BASE}/log-in-or-create-account`, proxy);
  }

  // Step 4: Submit password
  logger.info(`[OAuth] Submitting password...`);
  let loginVerifier = "";
  let pwData;
  let pwErr = null;
  try {
    pwData = await passwordVerify(cycleTLS, password, jar, ua, proxy);
    loginVerifier = pwData.login_verifier || pwData.loginVerifier || "";
  } catch (e) {
    pwErr = e;
    logger.warn(`[OAuth] Password verify failed: ${e.message}`);
  }

  // Step 5: Handle OTP if password verify redirects to email-verification
  if (!loginVerifier && pwData?.continue_url && pwData.continue_url.includes("email-verification")) {
    logger.info(`[OAuth] Email OTP required after password, waiting...`);
    const cu = pwData.continue_url.startsWith("http")
      ? pwData.continue_url
      : AUTH_BASE + pwData.continue_url;
    await loadPage(cycleTLS, cu, jar, ua, `${AUTH_BASE}/log-in/password`, proxy);

    // Wait 3 seconds for OTP to arrive
    await new Promise(r => setTimeout(r, 3000));

    const otpCode = await otpFn();
    if (!otpCode) throw new Error("OTP required but not provided");
    logger.info(`[OAuth] OTP received: ${otpCode}`);

    loginVerifier = await validateOTP(cycleTLS, otpCode, jar, ua, proxy);
  }

  // Step 5.5: Passwordless OTP fallback (if password was wrong)
  if (!loginVerifier && pwErr) {
    logger.info(`[OAuth] Trying passwordless OTP fallback...`);
    await sendOTP(cycleTLS, jar, ua, proxy);
    await new Promise(r => setTimeout(r, 3000));
    const otpCode = await otpFn();
    if (!otpCode) throw new Error("OTP required but not provided");
    logger.info(`[OAuth] OTP received: ${otpCode}`);
    loginVerifier = await validateOTP(cycleTLS, otpCode, jar, ua, proxy);
  }

  // Step 6: Workspace select → get final login_verifier
  let consentRedirectUrl = "";
  if (!loginVerifier && pwData?.continue_url) {
    // Load consent page, try workspace select with "personal" fallback
    const cu = pwData.continue_url.startsWith("http")
      ? pwData.continue_url
      : AUTH_BASE + pwData.continue_url;

    logger.info(`[OAuth] Workspace select...`);
    try {
      const wsData = await workspaceSelect(cycleTLS, "personal", jar, ua, proxy, cu);
      loginVerifier = wsData.login_verifier || wsData.loginVerifier || "";
      if (wsData.continue_url) {
        consentRedirectUrl = wsData.continue_url.startsWith("http")
          ? wsData.continue_url
          : AUTH_BASE + wsData.continue_url;
        // Extract login_verifier from continue_url if not in body
        if (!loginVerifier) {
          try {
            loginVerifier = new URL(consentRedirectUrl).searchParams.get("login_verifier") || "";
          } catch {}
        }
      }
    } catch (wsErr) {
      logger.warn(`[OAuth] workspace/select failed: ${wsErr.message}`);
    }
  }

  // Workspace select even if we have loginVerifier from password (standard path)
  if (!loginVerifier && !consentRedirectUrl) {
    logger.info(`[OAuth] Fallback workspace/select (personal)...`);
    const wsData = await workspaceSelect(cycleTLS, "personal", jar, ua, proxy);
    loginVerifier = wsData.login_verifier || wsData.loginVerifier || "";
    if (wsData.continue_url) {
      consentRedirectUrl = wsData.continue_url.startsWith("http")
        ? wsData.continue_url
        : AUTH_BASE + wsData.continue_url;
      if (!loginVerifier) {
        try {
          loginVerifier = new URL(consentRedirectUrl).searchParams.get("login_verifier") || "";
        } catch {}
      }
    }
  }

  if (!loginVerifier && !consentRedirectUrl) {
    throw new Error("No login_verifier or consent URL obtained after all steps");
  }

  // Step 7: Build consent URL and follow to auth code
  let consentUrl;
  if (consentRedirectUrl) {
    consentUrl = consentRedirectUrl;
  } else {
    const cp = new URLSearchParams({
      client_id: CLIENT_ID,
      code_challenge: challenge,
      code_challenge_method: "S256",
      codex_cli_simplified_flow: "true",
      id_token_add_organizations: "true",
      login_verifier: loginVerifier,
      originator: ORIGINATOR,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: SCOPE,
      state,
    });
    consentUrl = `${AUTH_BASE}/api/oauth/oauth2/auth?${cp.toString()}`;
  }

  logger.info(`[OAuth] Following consent chain to auth code...`);
  const authCode = await followToAuthCode(cycleTLS, consentUrl, jar, ua, proxy);
  if (!authCode) throw new Error("Failed to extract auth code from redirect chain");

  // Step 8: Token exchange
  logger.info(`[OAuth] Exchanging auth code for tokens...`);
  const tokens = await exchangeToken(cycleTLS, authCode, verifier, ua, proxy);

  logger.success(`[OAuth] ✓ Refresh Token obtained for ${email}`);
  return {
    refreshToken: tokens.refresh_token,
    accessToken: tokens.access_token,
    idToken: tokens.id_token,
  };
}

module.exports = { performLoginOAuth };
