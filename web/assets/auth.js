/* Clearsky auth: talks to Cognito's API directly (no hosted UI, no SDK).
   USER_PASSWORD_AUTH over HTTPS + NEW_PASSWORD_REQUIRED challenge +
   forgot-password flow + silent refresh with the refresh token. */

const AUTH = (() => {
  const KEY = "clearsky.tokens";

  function endpoint() {
    return `https://cognito-idp.${CONFIG.region}.amazonaws.com/`;
  }

  async function cognito(action, payload) {
    const resp = await fetch(endpoint(), {
      method: "POST",
      headers: {
        "content-type": "application/x-amz-json-1.1",
        "x-amz-target": `AWSCognitoIdentityProviderService.${action}`,
      },
      body: JSON.stringify(payload),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = new Error(data.message || data.__type || "auth failed");
      err.code = (data.__type || "").split("#").pop();
      throw err;
    }
    return data;
  }

  function save(result) {
    const now = Date.now();
    const cur = load() || {};
    localStorage.setItem(KEY, JSON.stringify({
      id_token: result.IdToken,
      access_token: result.AccessToken,
      refresh_token: result.RefreshToken || cur.refresh_token,
      expires_at: now + (result.ExpiresIn || 3600) * 1000,
    }));
  }

  function load() {
    try { return JSON.parse(localStorage.getItem(KEY)); }
    catch { return null; }
  }

  async function signIn(username, password) {
    const out = await cognito("InitiateAuth", {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: CONFIG.clientId,
      AuthParameters: { USERNAME: username, PASSWORD: password },
    });
    if (out.ChallengeName === "NEW_PASSWORD_REQUIRED") {
      return { challenge: "NEW_PASSWORD_REQUIRED", session: out.Session, username };
    }
    save(out.AuthenticationResult);
    return { ok: true };
  }

  async function completeNewPassword(username, newPassword, session) {
    const out = await cognito("RespondToAuthChallenge", {
      ClientId: CONFIG.clientId,
      ChallengeName: "NEW_PASSWORD_REQUIRED",
      Session: session,
      ChallengeResponses: { USERNAME: username, NEW_PASSWORD: newPassword },
    });
    save(out.AuthenticationResult);
    return { ok: true };
  }

  async function forgotPassword(username) {
    await cognito("ForgotPassword", { ClientId: CONFIG.clientId, Username: username });
  }

  async function confirmForgotPassword(username, code, newPassword) {
    await cognito("ConfirmForgotPassword", {
      ClientId: CONFIG.clientId, Username: username,
      ConfirmationCode: code, Password: newPassword,
    });
  }

  async function refresh() {
    const t = load();
    if (!t || !t.refresh_token) return false;
    try {
      const out = await cognito("InitiateAuth", {
        AuthFlow: "REFRESH_TOKEN_AUTH",
        ClientId: CONFIG.clientId,
        AuthParameters: { REFRESH_TOKEN: t.refresh_token },
      });
      save(out.AuthenticationResult);
      return true;
    } catch {
      return false;
    }
  }

  /* Valid id token, refreshing silently if within 2 min of expiry. */
  async function idToken() {
    const t = load();
    if (!t || !t.id_token) return null;
    if (t.expires_at - Date.now() < 120000 && !(await refresh())) return null;
    return (load() || {}).id_token;
  }

  function claims() {
    const t = load();
    if (!t || !t.id_token) return null;
    try { return JSON.parse(atob(t.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); }
    catch { return null; }
  }

  function signOut() {
    localStorage.removeItem(KEY);
    location.href = "/login";
  }

  /* Page guard: every page except login calls this first. */
  async function requireAuth() {
    if (await idToken()) return true;
    location.href = "/login";
    return false;
  }

  return { signIn, completeNewPassword, forgotPassword, confirmForgotPassword,
           idToken, claims, signOut, requireAuth };
})();
