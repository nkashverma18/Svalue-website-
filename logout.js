import { getCookie, readSession, clearCookie, requiredEnv, json } from "../_shared.js";

export async function onRequestPost({ request, env }) {
  try {
    const session = await readSession(getCookie(request, "sv_session"), requiredEnv(env, "SESSION_SECRET"));
    const csrf = request.headers.get("x-csrf-token") || "";
    if (!session || !csrf || csrf !== session.csrfToken) return json({ error: "Invalid session or CSRF token." }, 403);
    return json({ ok: true }, 200, { "set-cookie": clearCookie("sv_session") });
  } catch {
    return json({ error: "Unable to sign out." }, 500);
  }
}
