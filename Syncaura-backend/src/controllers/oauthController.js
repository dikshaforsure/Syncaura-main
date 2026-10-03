import { google } from "googleapis";
import axios from "axios";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pool from "../config/db.js";
import {
  generateAccessToken,
  generateRefreshToken,
  assignRefreshId,
} from "../utils/generateTokens.js";
import { getAccessToken as getGithubAccessToken } from "../services/githubAPI.js";

// Keep the current Google permissions unchanged in this first cleanup.
// Scope separation will be handled in a follow-up fix after this canonical
// OAuth path is deployed and verified.
const GOOGLE_OAUTH_SCOPES = [
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
  "https://www.googleapis.com/auth/calendar",
];

const JWT_STATE_SECRET =
  process.env.JWT_ACCESS_SECRET || "default_jwt_secret";

const getRedirectUri = (req) => {
  if (process.env.GOOGLE_REDIRECT_URI?.trim()) {
    return process.env.GOOGLE_REDIRECT_URI.trim();
  }

  const protocol = req.get("x-forwarded-proto") || req.protocol || "https";
  const host = req.get("host");

  return `${protocol}://${host}/api/auth/google/callback`;
};

const getOauth2Client = (req) => {
  const redirectUri = getRedirectUri(req);

  return {
    client: new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      redirectUri
    ),
    redirectUri,
  };
};

const getClientOrigin = (req) => {
  const rawOrigin =
    req.query.origin ||
    (req.get("referer") ? new URL(req.get("referer")).origin : null);

  return rawOrigin || process.env.CLIENT_URL || "https://flowbit.pages.dev";
};

const createCalendarState = (userId) =>
  jwt.sign(
    {
      purpose: "calendar",
      userId,
      t: Date.now(),
    },
    JWT_STATE_SECRET,
    { expiresIn: "10m" }
  );

const decodeOAuthState = (state) => {
  if (!state) return null;

  // New canonical state: signed JWT.
  try {
    const decoded = jwt.verify(state, JWT_STATE_SECRET);
    return {
      ...decoded,
      // The old /auth/google flow used a signed JWT containing only {id}.
      // Treat such state as a Calendar flow so an in-flight authorization
      // remains compatible while the duplicate route is retired.
      purpose: decoded.purpose || "calendar",
      userId: decoded.userId || decoded.id || decoded.sub || null,
    };
  } catch {
    // Existing login flow state was base64(JSON). Continue to accept it
    // during this migration so already-issued Google login URLs keep working.
    try {
      const parsed = JSON.parse(
        Buffer.from(state, "base64").toString("utf8")
      );

      return {
        ...parsed,
        purpose: parsed.purpose || "login",
      };
    } catch {
      return null;
    }
  }
};

const persistGoogleTokens = async (userId, tokens) => {
  await pool.query(
    `UPDATE users SET
      google_access_token = $1,
      google_refresh_token = COALESCE($2, google_refresh_token),
      google_scope = COALESCE($3, google_scope),
      google_token_type = COALESCE($4, google_token_type),
      google_expiry_date = COALESCE($5, google_expiry_date),
      updated_at = CURRENT_TIMESTAMP
    WHERE id = $6`,
    [
      tokens.access_token || null,
      tokens.refresh_token || null,
      tokens.scope || null,
      tokens.token_type || null,
      tokens.expiry_date || null,
      userId,
    ]
  );
};

/**
 * Initiate Google login/signup redirect.
 */
export const initiateGoogleLogin = async (req, res) => {
  const clientOrigin = getClientOrigin(req);

  try {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      console.error(
        "Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in backend environment variables."
      );

      return res.redirect(
        `${clientOrigin}/signin?error=${encodeURIComponent(
          "Google Client ID or Secret is not configured on the backend."
        )}`
      );
    }

    const { client: oauth2Client, redirectUri } = getOauth2Client(req);
    const statePayload = Buffer.from(
      JSON.stringify({
        origin: clientOrigin,
        t: Date.now(),
      })
    ).toString("base64");

    const authUrl = oauth2Client.generateAuthUrl({
      access_type: "offline",
      scope: GOOGLE_OAUTH_SCOPES,
      state: statePayload,
      prompt: "consent",
      redirect_uri: redirectUri,
    });

    return res.redirect(authUrl);
  } catch (error) {
    console.error("Google Login initiation error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to initiate Google Login",
    });
  }
};

/**
 * Initiate Google Calendar connection for an already authenticated
 * Syncaura user. The browser receives the Google authorization URL only;
 * the Syncaura access token stays in the Authorization header.
 */
export const initiateGoogleCalendarLogin = async (req, res) => {
  try {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      console.error(
        "Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in backend environment variables."
      );

      return res.status(500).json({
        success: false,
        message:
          "Google Client ID or Secret is not configured on the backend.",
      });
    }

    const { client: oauth2Client, redirectUri } = getOauth2Client(req);
    const state = createCalendarState(req.user.id);

    const authUrl = oauth2Client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: GOOGLE_OAUTH_SCOPES,
      state,
      redirect_uri: redirectUri,
    });

    return res.json({
      success: true,
      authUrl,
    });
  } catch (error) {
    console.error("Google Calendar authorization error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to initiate Google Calendar authorization",
    });
  }
};

/**
 * Handle the single Google OAuth callback used by both:
 * - Syncaura Google login
 * - Google Calendar connection
 */
export const handleGoogleCallback = async (req, res) => {
  const stateData = decodeOAuthState(req.query.state);
  let clientUrl = process.env.CLIENT_URL || "https://flowbit.pages.dev";

  if (stateData?.origin) {
    clientUrl = stateData.origin;
  }

  const isCalendarFlow = stateData?.purpose === "calendar";

  try {
    const { code } = req.query;

    if (!code) {
      const target = isCalendarFlow ? "meetings" : "signin";

      return res.redirect(
        `${clientUrl}/${target}?error=${encodeURIComponent(
          "Google authorization code missing"
        )}`
      );
    }

    if (!stateData) {
      return res.redirect(
        `${clientUrl}/signin?error=${encodeURIComponent(
          "Invalid or expired Google OAuth state"
        )}`
      );
    }

    const { client: oauth2Client, redirectUri } = getOauth2Client(req);
    const { tokens } = await oauth2Client.getToken({
      code,
      redirect_uri: redirectUri,
    });

    oauth2Client.setCredentials(tokens);

    // Calendar connection: associate Google Calendar tokens with the
    // already-authenticated Syncaura account represented by signed state.
    if (isCalendarFlow) {
      const targetUserId = stateData.userId;

      if (!targetUserId) {
        throw new Error("Google Calendar user context is missing");
      }

      const userRes = await pool.query(
        "SELECT id FROM users WHERE id = $1 AND is_active = true",
        [targetUserId]
      );

      if (userRes.rowCount === 0) {
        throw new Error("User not found or account deactivated");
      }

      await persistGoogleTokens(targetUserId, tokens);

      return res.redirect(
        `${clientUrl}/meetings?google_connected=true`
      );
    }

    // Normal Google login: fetch Google identity information.
    const oauth2 = google.oauth2({
      version: "v2",
      auth: oauth2Client,
    });

    const { data: userInfo } = await oauth2.userinfo.get();

    if (!userInfo.email) {
      return res.redirect(
        `${clientUrl}/signin?error=${encodeURIComponent(
          "Google account does not have a valid email address"
        )}`
      );
    }

    const email = userInfo.email.toLowerCase();

    let userRes = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    let user;

    if (userRes.rowCount > 0) {
      user = userRes.rows[0];
    } else {
      const dummyPassword = await bcrypt.hash(
        Math.random().toString(36),
        12
      );
      const name = userInfo.name || "Google User";

      const insertRes = await pool.query(
        "INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *",
        [name, email, dummyPassword, "user"]
      );

      user = insertRes.rows[0];
    }

    // Preserve current behavior for this first cleanup. Calendar scope
    // separation is deliberately a separate follow-up change.
    await persistGoogleTokens(user.id, tokens);

    const rid = assignRefreshId(user);

    await pool.query(
      "UPDATE users SET refresh_token_id = $1 WHERE id = $2",
      [rid, user.id]
    );

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user, rid);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.redirect(
      `${clientUrl}/auth/callback?token=${accessToken}&refreshToken=${refreshToken}&role=${user.role}&name=${encodeURIComponent(
        user.name
      )}`
    );
  } catch (error) {
    console.error("Google OAuth callback error:", error);

    const target = isCalendarFlow ? "meetings" : "signin";

    return res.redirect(
      `${clientUrl}/${target}?error=${encodeURIComponent(
        error.message || "Google OAuth failed"
      )}`
    );
  }
};

/**
 * Helper to fetch user details from GitHub
 */
const getGithubUser = async (accessToken) => {
  const { data: profile } = await axios.get("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  let email = profile.email;

  if (!email) {
    const { data: emails } = await axios.get(
      "https://api.github.com/user/emails",
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    );

    const primaryEmailObj =
      emails.find((e) => e.primary && e.verified) || emails[0];

    email = primaryEmailObj?.email;
  }

  return {
    email: email ? email.toLowerCase() : null,
    name: profile.name || profile.login || "GitHub User",
  };
};

/**
 * Handle GitHub callback, register or login user, and return JWT credentials as JSON
 */
export const handleGithubCallback = async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({
        message: "GitHub authorization code missing",
      });
    }

    const githubAccessToken = await getGithubAccessToken(code);
    const githubUser = await getGithubUser(githubAccessToken);

    if (!githubUser.email) {
      return res.status(400).json({
        message:
          "Could not retrieve a valid email from your GitHub profile",
      });
    }

    let userRes = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [githubUser.email]
    );

    let user;

    if (userRes.rowCount > 0) {
      user = userRes.rows[0];
    } else {
      const dummyPassword = await bcrypt.hash(
        Math.random().toString(36),
        12
      );

      const insertRes = await pool.query(
        "INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *",
        [githubUser.name, githubUser.email, dummyPassword, "user"]
      );

      user = insertRes.rows[0];
    }

    const rid = assignRefreshId(user);

    await pool.query(
      "UPDATE users SET refresh_token_id = $1 WHERE id = $2",
      [rid, user.id]
    );

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user, rid);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      tokens: {
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    console.error("GitHub OAuth login callback error:", error);

    return res.status(500).json({
      message: "GitHub Login failed",
      error: error.message,
    });
  }
};
