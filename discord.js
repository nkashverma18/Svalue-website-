import { randomToken, cookie, requiredEnv } from "../_shared.js";

export async function onRequestGet({ request, env }) {
  try {
    const clientId = requiredEnv(env, "DISCORD_CLIENT_ID");
    const redirectUri = requiredEnv(env, "DISCORD_REDIRECT_URI");
    requiredEnv(env, "DISCORD_CLIENT_SECRET");
    requiredEnv(env, "SESSION_SECRET");
    const state = randomToken(32);
    const url = new URL("https://discord.com/oauth2/authorize");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "identify");
    url.searchParams.set("state", state);
    return new Response(null, { status: 302, headers: {
      location: url.toString(),
      "cache-control": "no-store",
      "set-cookie": cookie("sv_oauth_state", state, 600),
    }});
  } catch (error) {
    return new Response(`Discord sign-in configuration error: ${error.message}`, { status: 500, headers: { "content-type": "text/plain; charset=utf-8" } });
  }
}
