const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const logger = require("./logger");

function base64UrlEncode(str) {
  return str
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function generatePKCE() {
  const verifier = base64UrlEncode(crypto.randomBytes(32));
  const challenge = base64UrlEncode(
    crypto.createHash("sha256").update(verifier).digest()
  );
  return { verifier, challenge };
}

const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"; // Codex Desktop
const REDIRECT_URI = "http://localhost:1455/auth/callback";
const SCOPE = "openid profile email offline_access api.connectors.read api.connectors.invoke";
const AUTH_BASE = "https://auth.openai.com";

const DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";

/**
 * Perform a FULL LOGIN to obtain OAuth tokens (RT, AT, IDT)
 */
async function performLoginOAuth(cycleTLS, email, password, proxyUrl, userAgent, fingerprint, otpFn) {
  const { verifier, challenge } = generatePKCE();
  const state = base64UrlEncode(crypto.randomBytes(16));
  const sessionId = uuidv4();
  const ua = userAgent || DEFAULT_UA;

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    code_challenge: challenge,
    code_challenge_method: "S256",
    codex_cli_simplified_flow: "true",
    id_token_add_organizations: "true",
    originator: "Codex Desktop",
    prompt: "login",
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: SCOPE,
    state: state,
  });

  const authorizeUrl = "https://auth.openai.com/oauth/authorize?" + params.toString();

  const baseHeaders = {
    "User-Agent": ua,
    "Accept-Language": "en-US,en;q=0.9",
    "sec-ch-ua": fingerprint?.sec || '"Chromium";v="147", "Not/A)Brand";v="24", "Google Chrome";v="147"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
  };

  const session = {
    jar: new Map(),
    capture(headers, url) {
        if (!headers) return;
        const domain = new URL(url).hostname;
        const setCookie = headers["Set-Cookie"] || headers["set-cookie"];
        if (!setCookie) return;
        const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (const c of cookies) {
            const match = c.match(/^([^=]+)=([^;]*)/);
            if (!match) continue;
            const cookieName = match[1].trim();
            const cookieValue = match[2];
            
            // Extract domain from cookie if present
            const domainMatch = c.match(/Domain=([^;]+)/i);
            const targetDomain = domainMatch ? domainMatch[1].replace(/^\./, "") : domain;
            
            if (!this.jar.has(targetDomain)) this.jar.set(targetDomain, new Map());
            this.jar.get(targetDomain).set(cookieName, cookieValue);
        }
    },
    headerFor(url) {
        const domain = new URL(url).hostname;
        const cookies = [];
        for (const [d, m] of this.jar) {
            if (domain === d || domain.endsWith("." + d)) {
                for (const [k, v] of m) cookies.push(`${k}=${v}`);
            }
        }
        return cookies.length ? cookies.join("; ") : undefined;
    }
  };

  // 1. Initial Authorize call
  logger.info(`[OAuth] Initiating login flow for ${email}...`);
  let resp = await cycleTLS(authorizeUrl, {
    headers: {
        ...baseHeaders,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    proxy: proxyUrl || undefined,
    disableRedirect: true,
    timeout: 30
  }, "get");
  
  if (resp.status === 0) throw new Error("Network error or timeout on initial authorize call");
  session.capture(resp.headers, authorizeUrl);

  // Follow to login page
  let currentUrl = resp.headers.Location || resp.headers.location;
  if (!currentUrl) throw new Error(`No redirect from authorize URL (Status: ${resp.status})`);
  if (!currentUrl.startsWith("http")) currentUrl = "https://auth.openai.com" + currentUrl;

  for (let i = 0; i < 5; i++) {
    const cookie = session.headerFor(currentUrl);
    resp = await cycleTLS(currentUrl, {
        headers: { ...baseHeaders, ...(cookie ? { Cookie: cookie } : {}) },
        proxy: proxyUrl || undefined,
        disableRedirect: true,
        timeout: 30
    }, "get");
    session.capture(resp.headers, currentUrl);
    const loc = resp.headers.Location || resp.headers.location;
    if (!loc) break;
    currentUrl = new URL(loc, currentUrl).href;
  }

  // 2. Submit Email
  logger.info(`[OAuth] Submitting email...`);
  const signinUrl = `${AUTH_BASE}/api/auth/signin/openai?prompt=login&screen_hint=login&login_hint=${encodeURIComponent(email)}&auth_session_logging_id=${sessionId}`;
  const signinBody = new URLSearchParams({
    callbackUrl: "/",
    csrfToken: "dummy",
    json: "true"
  }).toString();

  const sCookie = session.headerFor(signinUrl);
  resp = await cycleTLS(signinUrl, {
    body: signinBody,
    headers: { 
        ...baseHeaders, 
        ...(sCookie ? { Cookie: sCookie } : {}),
        "Content-Type": "application/x-www-form-urlencoded",
        Referer: currentUrl
    },
    proxy: proxyUrl || undefined,
    timeout: 30
  }, "post");
  session.capture(resp.headers, signinUrl);

  let data;
  try {
    data = typeof resp.data === 'string' ? JSON.parse(resp.data) : resp.data;
  } catch(e) { }
  
  currentUrl = data?.url || resp.headers.Location || resp.headers.location;
  if (!currentUrl) throw new Error("Failed to get next URL after email submission");
  if (!currentUrl.startsWith("http")) currentUrl = AUTH_BASE + currentUrl;

  // Follow to password page
  for (let i = 0; i < 5; i++) {
    const cookie = session.headerFor(currentUrl);
    resp = await cycleTLS(currentUrl, {
        headers: { ...baseHeaders, ...(cookie ? { Cookie: cookie } : {}) },
        proxy: proxyUrl || undefined,
        disableRedirect: true,
        timeout: 30
    }, "get");
    session.capture(resp.headers, currentUrl);
    const loc = resp.headers.Location || resp.headers.location;
    if (!loc) break;
    currentUrl = new URL(loc, currentUrl).href;
  }

  // 3. Submit Password
  logger.info(`[OAuth] Submitting password...`);
  const verifyUrl = `${AUTH_BASE}/api/accounts/password/verify`;
  const verifyBody = JSON.stringify({ password: password });
  
  const vCookie = session.headerFor(verifyUrl);
  resp = await cycleTLS(verifyUrl, {
    body: verifyBody,
    headers: { 
        ...baseHeaders, 
        ...(vCookie ? { Cookie: vCookie } : {}),
        "Content-Type": "application/json",
        Referer: currentUrl
    },
    proxy: proxyUrl || undefined,
    timeout: 30
  }, "post");
  session.capture(resp.headers, verifyUrl);

  try {
    data = typeof resp.data === 'string' ? JSON.parse(resp.data) : resp.data;
  } catch(e) { }

  if (resp.status !== 200) {
      throw new Error(`Password verification failed (${resp.status}): ${JSON.stringify(data)}`);
  }

  currentUrl = data?.continue_url || resp.headers.Location || resp.headers.location;
  if (!currentUrl) throw new Error("Failed to get next URL after password submission");
  if (!currentUrl.startsWith("http")) currentUrl = AUTH_BASE + currentUrl;

  // 4. Handle OTP if needed
  if (currentUrl.includes("/email-verification")) {
      logger.info(`[OAuth] Email verification required, triggering OTP...`);
      await cycleTLS(`${AUTH_BASE}/api/accounts/email-otp/send`, {
          headers: { ...baseHeaders, Cookie: session.headerFor(AUTH_BASE) },
          proxy: proxyUrl || undefined,
          timeout: 30
      }, "get");

      const otp = await otpFn();
      if (!otp) throw new Error("OTP required but not provided");
      logger.info(`[OAuth] OTP received: ${otp}, validating...`);

      resp = await cycleTLS(`${AUTH_BASE}/api/accounts/email-otp/validate`, {
          body: JSON.stringify({ code: otp.toString() }),
          headers: { 
              ...baseHeaders, 
              Cookie: session.headerFor(AUTH_BASE),
              "Content-Type": "application/json"
          },
          proxy: proxyUrl || undefined,
          timeout: 30
      }, "post");
      
      try {
        data = typeof resp.data === 'string' ? JSON.parse(resp.data) : resp.data;
      } catch(e) { }

      currentUrl = data?.continue_url || resp.headers.Location || resp.headers.location;
      if (!currentUrl) throw new Error("Failed to get continue URL after OTP");
      if (!currentUrl.startsWith("http")) currentUrl = AUTH_BASE + currentUrl;
  }

  // 5. Final Callback
  logger.info(`[OAuth] Finalizing callback...`);
  let authCode = null;
  for (let i = 0; i < 15; i++) {
    const cookie = session.headerFor(currentUrl);
    resp = await cycleTLS(currentUrl, {
        headers: { ...baseHeaders, ...(cookie ? { Cookie: cookie } : {}) },
        proxy: proxyUrl || undefined,
        disableRedirect: true,
        timeout: 30
    }, "get");
    session.capture(resp.headers, currentUrl);
    
    const loc = resp.headers.Location || resp.headers.location;
    if (loc) {
        currentUrl = new URL(loc, currentUrl).href;
        if (currentUrl.includes("code=")) {
            authCode = new URL(currentUrl).searchParams.get("code");
            break;
        }
    } else {
        break;
    }
  }

  if (!authCode) throw new Error("Failed to obtain Auth Code from login flow");

  // 6. Token Exchange
  logger.info(`[OAuth] Exchanging code for tokens...`);
  const tokenUrl = "https://auth.openai.com/oauth/token";
  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    code: authCode,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  }).toString();

  resp = await cycleTLS(tokenUrl, {
    body: tokenBody,
    headers: {
      ...baseHeaders,
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    },
    proxy: proxyUrl || undefined,
    timeout: 30
  }, "post");

  try {
    data = typeof resp.data === "string" ? JSON.parse(resp.data) : resp.data;
  } catch (e) {
    throw new Error(`Failed to parse token response: ${resp.data}`);
  }

  if (!data.refresh_token) {
    throw new Error(`No refresh_token in response: ${JSON.stringify(data)}`);
  }

  logger.success(`[OAuth] Refresh Token obtained successfully!`);
  return {
    refreshToken: data.refresh_token,
    accessToken: data.access_token,
    idToken: data.id_token,
  };
}

module.exports = {
  performLoginOAuth,
};
