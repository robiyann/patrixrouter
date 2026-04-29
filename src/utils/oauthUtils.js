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

/**
 * Perform a FULL LOGIN to obtain OAuth tokens (RT, AT, IDT)
 * This is needed because silent OAuth often fails for long-lived refresh tokens.
 */
async function performLoginOAuth(cycleTLS, email, password, proxyUrl, userAgent, fingerprint, otpFn) {
  const { verifier, challenge } = generatePKCE();
  const state = base64UrlEncode(crypto.randomBytes(16));
  const sessionId = uuidv4();

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
    "User-Agent": userAgent,
    "Accept-Language": "en-US,en;q=0.9",
    "sec-ch-ua": fingerprint.sec || '"Chromium";v="147", "Not/A)Brand";v="24", "Google Chrome";v="147"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
  };

  const session = {
    jar: new Map(),
    capture(headers, url) {
        const domain = new URL(url).hostname;
        const setCookie = headers["Set-Cookie"] || headers["set-cookie"];
        if (!setCookie) return;
        const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (const c of cookies) {
            const match = c.match(/^([^=]+)=([^;]*)/);
            if (!match) continue;
            if (!this.jar.has(domain)) this.jar.set(domain, new Map());
            this.jar.get(domain).set(match[1].trim(), match[2]);
        }
    },
    headerFor(url) {
        const domain = new URL(url).hostname;
        const cookies = [];
        for (const [d, m] of this.jar) {
            if (domain.includes(d)) {
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
  }, "get");
  session.capture(resp.headers, authorizeUrl);

  // Follow to login page
  let currentUrl = resp.headers.Location || resp.headers.location;
  if (!currentUrl) throw new Error("No redirect from authorize URL");

  for (let i = 0; i < 5; i++) {
    const cookie = session.headerFor(currentUrl);
    resp = await cycleTLS(currentUrl, {
        headers: { ...baseHeaders, ...(cookie ? { Cookie: cookie } : {}) },
        proxy: proxyUrl || undefined,
        disableRedirect: true,
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
    csrfToken: "dummy", // Usually not checked strictly here if cookies are right
    json: "true"
  }).toString();

  const cookie = session.headerFor(signinUrl);
  resp = await cycleTLS(signinUrl, signinBody, {
    headers: { 
        ...baseHeaders, 
        ...(cookie ? { Cookie: cookie } : {}),
        "Content-Type": "application/x-www-form-urlencoded"
    },
    proxy: proxyUrl || undefined,
  }, "post");
  session.capture(resp.headers, signinUrl);

  let data;
  try {
    data = typeof resp.data === 'string' ? JSON.parse(resp.data) : resp.data;
  } catch(e) { 
      // fallback
  }
  
  currentUrl = data?.url || resp.headers.Location || resp.headers.location;
  if (!currentUrl) throw new Error("Failed to get next URL after email submission");

  // Follow to password page
  for (let i = 0; i < 5; i++) {
    const cookie = session.headerFor(currentUrl);
    resp = await cycleTLS(currentUrl, {
        headers: { ...baseHeaders, ...(cookie ? { Cookie: cookie } : {}) },
        proxy: proxyUrl || undefined,
        disableRedirect: true,
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
  resp = await cycleTLS(verifyUrl, verifyBody, {
    headers: { 
        ...baseHeaders, 
        ...(vCookie ? { Cookie: vCookie } : {}),
        "Content-Type": "application/json",
        Referer: currentUrl
    },
    proxy: proxyUrl || undefined,
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
      logger.info(`[OAuth] Email verification required, waiting for OTP...`);
      // Trigger OTP send
      await cycleTLS(`${AUTH_BASE}/api/accounts/email-otp/send`, {
          headers: { ...baseHeaders, Cookie: session.headerFor(AUTH_BASE) },
          proxy: proxyUrl || undefined
      }, "get");

      const otp = await otpFn();
      if (!otp) throw new Error("OTP required but not provided");

      resp = await cycleTLS(`${AUTH_BASE}/api/accounts/email-otp/validate`, JSON.stringify({ code: otp.toString() }), {
          headers: { 
              ...baseHeaders, 
              Cookie: session.headerFor(AUTH_BASE),
              "Content-Type": "application/json"
          },
          proxy: proxyUrl || undefined
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
  for (let i = 0; i < 10; i++) {
    const cookie = session.headerFor(currentUrl);
    resp = await cycleTLS(currentUrl, {
        headers: { ...baseHeaders, ...(cookie ? { Cookie: cookie } : {}) },
        proxy: proxyUrl || undefined,
        disableRedirect: true,
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

  resp = await cycleTLS(tokenUrl, tokenBody, {
    headers: {
      ...baseHeaders,
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    },
    proxy: proxyUrl || undefined,
  }, "post");

  try {
    data = typeof resp.data === "string" ? JSON.parse(resp.data) : resp.data;
  } catch (e) {
    throw new Error(`Failed to parse token response: ${resp.data}`);
  }

  if (!data.refresh_token) {
    throw new Error(`No refresh_token in response: ${JSON.stringify(data)}`);
  }

  return {
    refreshToken: data.refresh_token,
    accessToken: data.access_token,
    idToken: data.id_token,
  };
}

module.exports = {
  performLoginOAuth,
};
