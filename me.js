import { getCookie, readSession, json, requiredEnv } from "../_shared.js";

export async function onRequestGet({ request, env }) {
  try {
    const session = await readSession(getCookie(request, "sv_session"), requiredEnv(env, "SESSION_SECRET"));
    if (!session?.user) return json({ authenticated: false, csrfToken: "" });
    return json({ authenticated: true, user: session.user, csrfToken: session.csrfToken || "" });
  } catch {
    return json({ authenticated: false, csrfToken: "" });
  }
}
