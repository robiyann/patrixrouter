const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

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

async function performSilentOAuth(cycleTLS, jar, proxyUrl, userAgent, fingerprint) {
  const { verifier, challenge } = generatePKCE();
  const state = base64UrlEncode(crypto.randomBytes(16));

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

  const headers = {
    "User-Agent": userAgent,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "sec-ch-ua": fingerprint.sec,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
  };

  let currentUrl = authorizeUrl;
  let authCode = null;

  // Follow redirect chain
  for (let i = 0; i < 15; i++) {
    const cookieHeader = jar.headerFor(currentUrl);
    const resp = await cycleTLS(currentUrl, {
      headers: {
        ...headers,
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
      },
      proxy: proxyUrl || undefined,
      disableRedirect: true,
    }, "get");

    jar.capture(resp.headers, resp.finalUrl || currentUrl);

    const location = resp.headers?.Location || resp.headers?.location;
    if (location) {
      currentUrl = new URL(location, currentUrl).href;
      if (currentUrl.includes("localhost:1455")) {
        const urlObj = new URL(currentUrl);
        authCode = urlObj.searchParams.get("code");
        break;
      }
    } else if (resp.status === 200) {
      // If we hit a 200 page instead of a redirect, it might be a login/consent page
      // In silent mode, we expect session cookies to bypass this.
      throw new Error(`Silent OAuth failed: Hit 200 at ${currentUrl}`);
    } else {
      throw new Error(`Silent OAuth failed: Status ${resp.status} at ${currentUrl}`);
    }
  }

  if (!authCode) {
    throw new Error("Failed to obtain Auth Code from redirect chain");
  }

  // Token Exchange
  const tokenUrl = "https://auth.openai.com/oauth/token";
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: authCode,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  });

  const tokenResp = await cycleTLS(tokenUrl, {
    headers: {
      "User-Agent": userAgent,
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    },
    body: body.toString(),
    proxy: proxyUrl || undefined,
  }, "post");

  let data;
  try {
    data = typeof tokenResp.data === "string" ? JSON.parse(tokenResp.data) : tokenResp.data;
  } catch (e) {
    throw new Error(`Failed to parse token response: ${tokenResp.data}`);
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
  performSilentOAuth,
};
