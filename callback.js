import { getCookie, randomToken, signSession, cookie, clearCookie, requiredEnv, avatarUrl } from "../../_shared.js";

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const savedState = getCookie(request, "sv_oauth_state");
  const clearState = clearCookie("sv_oauth_state");
  if (!code || !state || !savedState || state !== savedState) {
    return new Response("Discord sign-in could not be verified. Please go back and try again.", { status: 400, headers: { "content-type": "text/plain; charset=utf-8", "set-cookie": clearState } });
  }
  try {
    const clientId = requiredEnv(env, "DISCORD_CLIENT_ID");
    const clientSecret = requiredEnv(env, "DISCORD_CLIENT_SECRET");
    const redirectUri = requiredEnv(env, "DISCORD_REDIRECT_URI");
    const sessionSecret = requiredEnv(env, "SESSION_SECRET");

    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, grant_type: "authorization_code", code, redirect_uri: redirectUri }),
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) throw new Error("Discord token exchange failed. Check the Client Secret and Redirect URI.");

    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { authorization: `Bearer ${tokenData.access_token}` },
    });
    const discordUser = await userResponse.json();
    if (!userResponse.ok || !discordUser.id) throw new Error("Could not retrieve the Discord profile.");

    const csrfToken = randomToken(24);
    const user = {
      id: discordUser.id,
      username: discordUser.username,
      globalName: discordUser.global_name || discordUser.username,
      avatarUrl: avatarUrl(discordUser),
    };
    const session = await signSession({ user, csrfToken, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 }, sessionSecret);
    const headers = new Headers({ location: "/?discord=connected", "cache-control": "no-store" });
    headers.append("set-cookie", clearState);
    headers.append("set-cookie", cookie("sv_session", session, 7 * 24 * 60 * 60));
    return new Response(null, { status: 302, headers });
  } catch (error) {
    return new Response(`Discord sign-in failed: ${error.message}`, { status: 500, headers: { "content-type": "text/plain; charset=utf-8", "set-cookie": clearState } });
  }
}
