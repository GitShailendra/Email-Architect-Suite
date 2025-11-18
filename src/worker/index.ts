import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { setCookie } from "hono/cookie";
import {
  getOAuthRedirectUrl,
  exchangeCodeForSessionToken,
  deleteSession,
  MOCHA_SESSION_TOKEN_COOKIE_NAME,
  authMiddleware,
} from "@getmocha/users-service/backend";
import { getCookie } from "hono/cookie";
import { 
  CreateSequenceSchema, 
  CreateEmailBlockSchema, 
  UpdateEmailBlockSchema,
  CreateConnectionSchema,
  CreateTemplateSchema,
  ExportSequenceSchema,
  GenerateContentSchema
} from "@/shared/types";
import OpenAI from "openai";
import { v4 as uuidv4 } from "uuid";

const app = new Hono<{ Bindings: Env }>();

const ADMIN_SESSION_COOKIE_NAME = 'admin_session_token';

// Admin authentication middleware
const adminAuthMiddleware = async (c: any, next: any) => {
  const sessionToken = getCookie(c, ADMIN_SESSION_COOKIE_NAME);
  
  if (!sessionToken) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  const db = c.env.DB;
  const session = await db.prepare(
    "SELECT * FROM admin_sessions WHERE token = ? AND expires_at > datetime('now')"
  ).bind(sessionToken).first();
  
  if (!session) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  await next();
};
// Custom authentication middleware for Google OAuth
const authMiddleware = async (c: any, next: any) => {
  const sessionToken = getCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME);
  
  if (!sessionToken) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  const db = c.env.DB;
  const session = await db.prepare(
    "SELECT * FROM user_sessions WHERE token = ? AND expires_at > datetime('now')"
  ).bind(sessionToken).first();
  
  if (!session) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Set user object
  c.set('user', {
    id: session.user_id,
    email: session.email,
  });
  
  await next();
};

// ===== ADMIN ROUTES =====

// Admin login
app.post("/api/admin/login", async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  
  const { email, password } = body;
  
  // Check credentials (hardcoded for now)
  if (email === 'gotayjust@hotmail.com' && password === 'inderpalastra11') {
    // Create session
    const sessionId = uuidv4();
    const token = uuidv4();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
    
    await db.prepare(`
      INSERT INTO admin_sessions (id, admin_email, token, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(sessionId, email, token, now.toISOString(), expiresAt.toISOString()).run();
    
    setCookie(c, ADMIN_SESSION_COOKIE_NAME, token, {
      httpOnly: true,
      path: "/",
      sameSite: "none",
      secure: true,
      maxAge: 24 * 60 * 60, // 24 hours
    });
    
    return c.json({ success: true }, 200);
  }
  
  return c.json({ error: "Invalid credentials" }, 401);
});

// Admin logout
app.post("/api/admin/logout", async (c) => {
  const db = c.env.DB;
  const sessionToken = getCookie(c, ADMIN_SESSION_COOKIE_NAME);
  
  if (sessionToken) {
    await db.prepare("DELETE FROM admin_sessions WHERE token = ?").bind(sessionToken).run();
  }
  
  setCookie(c, ADMIN_SESSION_COOKIE_NAME, '', {
    httpOnly: true,
    path: '/',
    sameSite: 'none',
    secure: true,
    maxAge: 0,
  });
  
  return c.json({ success: true }, 200);
});

// Get all users (admin only)
app.get("/api/admin/users", adminAuthMiddleware, async (c) => {
  const db = c.env.DB;
  
  // Fetch all user credits records
  const creditsRecords = await db.prepare("SELECT * FROM user_credits").all();
  
  // Get user details and credits
  const users = [];
  for (const creditsRecord of creditsRecords.results as any[]) {
    const userId = creditsRecord.user_id;
    
    // Get the first sequence to determine when user joined
    const userSequence = await db.prepare(
      "SELECT user_id, created_at FROM sequences WHERE user_id = ? ORDER BY created_at ASC LIMIT 1"
    ).bind(userId).first();
    
    // Use sequence creation date or credit record date
    const createdAt = userSequence?.created_at || creditsRecord.last_updated || new Date().toISOString();
    
    users.push({
      id: userId,
      email: creditsRecord.email || userId, // Use stored email from user_credits
      created_at: createdAt,
      user_id: userId,
      credits_balance: creditsRecord.credits_balance || 0,
      total_credits_used: creditsRecord.total_credits_used || 0,
      plan: creditsRecord.plan || 'Basic',
      is_active: creditsRecord.is_active !== false,
    });
  }
  
  return c.json(users);
});

// Update user (admin only)
app.put("/api/admin/users/:userId", adminAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const userId = c.req.param("userId");
  const body = await c.req.json();
  const now = new Date().toISOString();
  
  // Update user credits and plan
  await db.prepare(`
    UPDATE user_credits 
    SET credits_balance = ?, plan = ?, last_updated = ?
    WHERE user_id = ?
  `).bind(body.credits_balance, body.plan, now, userId).run();
  
  // Note: Email changes would require integration with Mocha's user service
  // For now, we'll skip email updates
  
  return c.json({ success: true });
});

// Toggle user active status (admin only)
app.post("/api/admin/users/:userId/toggle-active", adminAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const userId = c.req.param("userId");
  const now = new Date().toISOString();
  
  // Get current status
  const credits = await db.prepare(
    "SELECT is_active FROM user_credits WHERE user_id = ?"
  ).bind(userId).first();
  
  const newStatus = !(credits?.is_active !== false);
  
  await db.prepare(`
    UPDATE user_credits 
    SET is_active = ?, last_updated = ?
    WHERE user_id = ?
  `).bind(newStatus, now, userId).run();
  
  return c.json({ success: true });
});

// ===== AUTH ROUTES =====

// Get OAuth redirect URL
app.get('/api/oauth/google/redirect_url', async (c) => {
  const clientId = c.env.GOOGLE_CLIENT_ID;
  const redirectUri = 'http://localhost:5173/auth/callback'; // Adjust if your port is different
  
  if (!clientId) {
    return c.json({ error: "Google Client ID not configured" }, 500);
  }
  
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${clientId}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `response_type=code&` +
    `scope=${encodeURIComponent('email profile openid')}&` +
    `access_type=offline&` +
    `prompt=consent`;

  return c.json({ redirectUrl: authUrl }, 200);
});


// Exchange code for session token
app.post("/api/sessions", async (c) => {
  const body = await c.req.json();
  const db = c.env.DB;

  if (!body.code) {
    return c.json({ error: "No authorization code provided" }, 400);
  }

  try {
    // Exchange code for tokens with Google
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: body.code,
        client_id: c.env.GOOGLE_CLIENT_ID,
        client_secret: c.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: 'http://localhost:5173/auth/callback',
        grant_type: 'authorization_code',
      }),
    });

    const tokens = await tokenResponse.json();
    
    if (!tokenResponse.ok) {
      console.error('Token exchange error:', tokens);
      return c.json({ error: "Failed to exchange code for tokens" }, 400);
    }

    // Get user info from Google
    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    const userInfo = await userInfoResponse.json();
    
    // Create session token
    const sessionToken = uuidv4();
    const userId = userInfo.id;
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString();

    // Store session in database
    await db.prepare(`
      INSERT OR REPLACE INTO user_sessions (id, user_id, email, token, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(uuidv4(), userId, userInfo.email, sessionToken, now, expiresAt).run();

    setCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME, sessionToken, {
      httpOnly: true,
      path: "/",
      sameSite: "none",
      secure: true,
      maxAge: 60 * 24 * 60 * 60,
    });

    return c.json({ success: true }, 200);
  } catch (error) {
    console.error('OAuth error:', error);
    return c.json({ error: "Authentication failed" }, 500);
  }
});
// ===== EMAIL/PASSWORD AUTH ROUTES =====

// Email signup
app.post("/api/auth/signup", async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  
  const { email, password, full_name } = body;
  
  // Validate input
  if (!email || !password) {
    return c.json({ error: "Email and password are required" }, 400);
  }
  
  if (password.length < 8) {
    return c.json({ error: "Password must be at least 8 characters" }, 400);
  }
  
  // Check if user already exists
  const existingUser = await db.prepare(
    "SELECT id FROM users WHERE email = ?"
  ).bind(email.toLowerCase()).first();
  
  if (existingUser) {
    return c.json({ error: "Email already registered" }, 409);
  }
  
  try {
    // Hash password (simple bcrypt-like approach for Cloudflare Workers)
    const passwordHash = await hashPassword(password);
    
    const userId = uuidv4();
    const now = new Date().toISOString();
    
    // Create user
    await db.prepare(`
      INSERT INTO users (id, email, password_hash, full_name, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(userId, email.toLowerCase(), passwordHash, full_name || null, now, now).run();
    
    // Create session
    const sessionToken = uuidv4();
    const expiresAt = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString();
    
    await db.prepare(`
      INSERT INTO user_sessions (id, user_id, email, token, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(uuidv4(), userId, email.toLowerCase(), sessionToken, now, expiresAt).run();
    
    // Initialize user credits
    await db.prepare(`
      INSERT INTO user_credits (user_id, credits_balance, total_credits_used, last_updated, email)
      VALUES (?, 10000, 0, ?, ?)
    `).bind(userId, now, email.toLowerCase()).run();
    
    setCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME, sessionToken, {
      httpOnly: true,
      path: "/",
      sameSite: "none",
      secure: true,
      maxAge: 60 * 24 * 60 * 60,
    });
    
    return c.json({ success: true, user: { id: userId, email: email.toLowerCase() } }, 201);
  } catch (error) {
    console.error('Signup error:', error);
    return c.json({ error: "Failed to create account" }, 500);
  }
});

// Email login
app.post("/api/auth/login", async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  
  const { email, password } = body;
  
  if (!email || !password) {
    return c.json({ error: "Email and password are required" }, 400);
  }
  
  try {
    // Get user
    const user = await db.prepare(
      "SELECT id, email, password_hash FROM users WHERE email = ?"
    ).bind(email.toLowerCase()).first();
    
    if (!user) {
      return c.json({ error: "Invalid email or password" }, 401);
    }
    
    // Verify password
    const isValid = await verifyPassword(password, user.password_hash as string);
    
    if (!isValid) {
      return c.json({ error: "Invalid email or password" }, 401);
    }
    
    // Create session
    const sessionToken = uuidv4();
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString();
    
    await db.prepare(`
      INSERT INTO user_sessions (id, user_id, email, token, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(uuidv4(), user.id, user.email, sessionToken, now, expiresAt).run();
    
    setCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME, sessionToken, {
      httpOnly: true,
      path: "/",
      sameSite: "none",
      secure: true,
      maxAge: 60 * 24 * 60 * 60,
    });
    
    return c.json({ success: true, user: { id: user.id, email: user.email } }, 200);
  } catch (error) {
    console.error('Login error:', error);
    return c.json({ error: "Login failed" }, 500);
  }
});

// Password hashing helper (add at the top of the file after imports)
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const passwordHash = await hashPassword(password);
  return passwordHash === hash;
}


// Get current user
app.get("/api/users/me", authMiddleware, async (c) => {
  return c.json(c.get("user"));
});

// Get user credits
app.get("/api/users/me/credits", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Get or create user credits record
  let userCredits = await db.prepare(
    "SELECT * FROM user_credits WHERE user_id = ?"
  ).bind(user.id).first();
  
  const now = new Date().toISOString();
  
  if (!userCredits) {
    // Initialize credits for new user
    await db.prepare(`
      INSERT INTO user_credits (user_id, credits_balance, total_credits_used, last_updated, email)
      VALUES (?, 10000, 0, ?, ?)
    `).bind(user.id, now, user.email).run();
    
    userCredits = await db.prepare(
      "SELECT * FROM user_credits WHERE user_id = ?"
    ).bind(user.id).first();
  } else {
    // Update email if it's missing or different (sync with auth service)
    if (!userCredits.email || userCredits.email !== user.email) {
      await db.prepare(`
        UPDATE user_credits 
        SET email = ?, last_updated = ?
        WHERE user_id = ?
      `).bind(user.email, now, user.id).run();
      
      userCredits = await db.prepare(
        "SELECT * FROM user_credits WHERE user_id = ?"
      ).bind(user.id).first();
    }
  }
  
  return c.json(userCredits);
});

// Logout
app.get('/api/logout', async (c) => {
  const db = c.env.DB;
  const sessionToken = getCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME);

  if (typeof sessionToken === 'string') {
    await db.prepare("DELETE FROM user_sessions WHERE token = ?").bind(sessionToken).run();
  }

  setCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME, '', {
    httpOnly: true,
    path: '/',
    sameSite: 'none',
    secure: true,
    maxAge: 0,
  });

  return c.json({ success: true }, 200);
});


// ===== SEQUENCE ROUTES =====

// Get all sequences for authenticated user
app.get("/api/sequences", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  const sequences = await db.prepare(
    "SELECT * FROM sequences WHERE user_id = ? ORDER BY created_at DESC"
  ).bind(user.id).all();
  
  return c.json(sequences.results);
});

// Create sequence
app.post("/api/sequences", authMiddleware, zValidator("json", CreateSequenceSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const body = c.req.valid("json");
  const id = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  await db.prepare(`
    INSERT INTO sequences (id, name, description, user_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(id, body.name, body.description || "", user.id, now, now).run();
  
  const sequence = await db.prepare("SELECT * FROM sequences WHERE id = ?").bind(id).first();
  return c.json(sequence);
});

// Update sequence
app.put("/api/sequences/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  const body = await c.req.json();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify ownership
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  // Validate input
  if (!body.name || !body.name.trim()) {
    return c.json({ error: "Name is required" }, 400);
  }
  
  // Update sequence
  await db.prepare(`
    UPDATE sequences SET name = ?, description = ?, updated_at = ? WHERE id = ?
  `).bind(body.name.trim(), body.description || "", now, sequenceId).run();
  
  const updatedSequence = await db.prepare("SELECT * FROM sequences WHERE id = ?").bind(sequenceId).first();
  return c.json(updatedSequence);
});

// Get sequence with blocks and connections
app.get("/api/sequences/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  const blocks = await db.prepare("SELECT * FROM email_blocks WHERE sequence_id = ?").bind(sequenceId).all();
  const connections = await db.prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).all();
  
  return c.json({
    sequence,
    blocks: blocks.results,
    connections: connections.results
  });
});

// Delete sequence
app.delete("/api/sequences/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify ownership
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  // Delete in order: connections, blocks, sequence
  await db.prepare("DELETE FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).run();
  await db.prepare("DELETE FROM email_blocks WHERE sequence_id = ?").bind(sequenceId).run();
  await db.prepare("DELETE FROM sequences WHERE id = ?").bind(sequenceId).run();
  
  return c.json({ success: true });
});

// Duplicate sequence
app.post("/api/sequences/:id/duplicate", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  const newSequenceId = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Get original sequence
  const originalSequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!originalSequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  // Duplicate sequence
  await db.prepare(`
    INSERT INTO sequences (id, name, description, user_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    newSequenceId, 
    `${String(originalSequence.name)} (Copy)`, 
    originalSequence.description, 
    user.id, 
    now, 
    now
  ).run();
  
  // Get original blocks
  const originalBlocks = await db.prepare("SELECT * FROM email_blocks WHERE sequence_id = ?").bind(sequenceId).all();
  const blockIdMap = new Map<string, string>();
  
  // Duplicate blocks
  for (const block of originalBlocks.results as any[]) {
    const newBlockId = uuidv4();
    blockIdMap.set(block.id, newBlockId);
    
    await db.prepare(`
      INSERT INTO email_blocks (id, sequence_id, type, name, subject_line, preview_text, body_copy, cta_text, cta_url, send_delay_hours, position_x, position_y, notes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      newBlockId, newSequenceId, block.type, block.name, block.subject_line, block.preview_text,
      block.body_copy, block.cta_text, block.cta_url, block.send_delay_hours,
      block.position_x, block.position_y, block.notes, now, now
    ).run();
  }
  
  // Duplicate connections
  const originalConnections = await db.prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).all();
  
  for (const connection of originalConnections.results as any[]) {
    const newConnectionId = uuidv4();
    const newSourceId = blockIdMap.get(connection.source_block_id);
    const newTargetId = blockIdMap.get(connection.target_block_id);
    
    if (newSourceId && newTargetId) {
      await db.prepare(`
        INSERT INTO sequence_connections (id, sequence_id, source_block_id, target_block_id, condition_type, custom_label, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(newConnectionId, newSequenceId, newSourceId, newTargetId, connection.condition_type, connection.custom_label || null, now, now).run();
    }
  }
  
  const newSequence = await db.prepare("SELECT * FROM sequences WHERE id = ?").bind(newSequenceId).first();
  return c.json(newSequence);
});

// ===== EMAIL BLOCK ROUTES =====

// Create email block
app.post("/api/sequences/:id/blocks", authMiddleware, zValidator("json", CreateEmailBlockSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  const body = c.req.valid("json");
  const blockId = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify sequence ownership
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  await db.prepare(`
    INSERT INTO email_blocks (id, sequence_id, type, name, position_x, position_y, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(blockId, sequenceId, body.type, body.name, body.position_x, body.position_y, now, now).run();
  
  const block = await db.prepare("SELECT * FROM email_blocks WHERE id = ?").bind(blockId).first();
  return c.json(block);
});

// Update email block
app.put("/api/blocks/:id", authMiddleware, zValidator("json", UpdateEmailBlockSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const blockId = c.req.param("id");
  const body = c.req.valid("json");
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify block ownership through sequence
  const block = await db.prepare(`
    SELECT eb.* FROM email_blocks eb
    JOIN sequences s ON eb.sequence_id = s.id
    WHERE eb.id = ? AND s.user_id = ?
  `).bind(blockId, user.id).first();
  
  if (!block) {
    return c.json({ error: "Block not found" }, 404);
  }
  
  const updates = Object.entries(body).filter(([_, value]) => value !== undefined);
  if (updates.length === 0) {
    return c.json({ error: "No fields to update" }, 400);
  }
  
  const setClause = updates.map(([key, _]) => `${key} = ?`).join(", ");
  const values = [...updates.map(([_, value]) => value), now, blockId];
  
  await db.prepare(`
    UPDATE email_blocks SET ${setClause}, updated_at = ? WHERE id = ?
  `).bind(...values).run();
  
  const updatedBlock = await db.prepare("SELECT * FROM email_blocks WHERE id = ?").bind(blockId).first();
  return c.json(updatedBlock);
});

// Duplicate block
app.post("/api/blocks/:id/duplicate", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const blockId = c.req.param("id");
  const newBlockId = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Fetch the source block from database to get latest content
  const sourceBlock = await db.prepare(`
    SELECT eb.* FROM email_blocks eb
    JOIN sequences s ON eb.sequence_id = s.id
    WHERE eb.id = ? AND s.user_id = ?
  `).bind(blockId, user.id).first();
  
  if (!sourceBlock) {
    return c.json({ error: "Block not found" }, 404);
  }
  
  // Calculate new position offset from original
  const newPositionX = (sourceBlock.position_x as number) + 350;
  const newPositionY = (sourceBlock.position_y as number) + 50;
  
  // Create new block with all content from source block
  await db.prepare(`
    INSERT INTO email_blocks (
      id, sequence_id, type, name, subject_line, preview_text, 
      body_copy, cta_text, cta_url, send_delay_hours, 
      position_x, position_y, notes, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    newBlockId,
    sourceBlock.sequence_id,
    sourceBlock.type,
    `${sourceBlock.name} (Copy)`,
    sourceBlock.subject_line || null,
    sourceBlock.preview_text || null,
    sourceBlock.body_copy || null,
    sourceBlock.cta_text || null,
    sourceBlock.cta_url || null,
    sourceBlock.send_delay_hours || 0,
    newPositionX,
    newPositionY,
    sourceBlock.notes || null,
    now,
    now
  ).run();
  
  // Return the newly created block
  const newBlock = await db.prepare("SELECT * FROM email_blocks WHERE id = ?").bind(newBlockId).first();
  return c.json(newBlock);
});

// Delete block
app.delete("/api/blocks/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const blockId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify block ownership through sequence
  const block = await db.prepare(`
    SELECT eb.* FROM email_blocks eb
    JOIN sequences s ON eb.sequence_id = s.id
    WHERE eb.id = ? AND s.user_id = ?
  `).bind(blockId, user.id).first();
  
  if (!block) {
    return c.json({ error: "Block not found" }, 404);
  }
  
  // Delete connections first
  await db.prepare("DELETE FROM sequence_connections WHERE source_block_id = ? OR target_block_id = ?").bind(blockId, blockId).run();
  
  // Delete block
  await db.prepare("DELETE FROM email_blocks WHERE id = ?").bind(blockId).run();
  
  return c.json({ success: true });
});

// ===== CONNECTION ROUTES =====

// Create connection
app.post("/api/connections", authMiddleware, zValidator("json", CreateConnectionSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const body = c.req.valid("json");
  const connectionId = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify sequence ownership
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(body.sequence_id, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  await db.prepare(`
    INSERT INTO sequence_connections (id, sequence_id, source_block_id, target_block_id, condition_type, custom_label, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(connectionId, body.sequence_id, body.source_block_id, body.target_block_id, body.condition_type, body.custom_label || null, now, now).run();
  
  const connection = await db.prepare("SELECT * FROM sequence_connections WHERE id = ?").bind(connectionId).first();
  return c.json(connection);
});

// Delete connection
app.delete("/api/connections/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const connectionId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify connection ownership through sequence
  const connection = await db.prepare(`
    SELECT sc.* FROM sequence_connections sc
    JOIN sequences s ON sc.sequence_id = s.id
    WHERE sc.id = ? AND s.user_id = ?
  `).bind(connectionId, user.id).first();
  
  if (!connection) {
    return c.json({ error: "Connection not found" }, 404);
  }
  
  await db.prepare("DELETE FROM sequence_connections WHERE id = ?").bind(connectionId).run();
  return c.json({ success: true });
});

// ===== TEMPLATE ROUTES =====

// Get public templates
app.get("/api/templates", async (c) => {
  const db = c.env.DB;
  const templates = await db.prepare(
    "SELECT * FROM sequence_templates WHERE is_public = TRUE ORDER BY created_at DESC"
  ).all();
  
  return c.json(templates.results);
});

// Get user's saved templates
app.get("/api/user-templates", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  const templates = await db.prepare(
    "SELECT * FROM user_templates WHERE user_id = ? ORDER BY created_at DESC"
  ).bind(user.id).all();
  
  return c.json(templates.results);
});

// Delete user template
app.delete("/api/user-templates/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const templateId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify ownership
  const template = await db.prepare(
    "SELECT * FROM user_templates WHERE id = ? AND user_id = ?"
  ).bind(templateId, user.id).first();
  
  if (!template) {
    return c.json({ error: "Template not found" }, 404);
  }
  
  await db.prepare("DELETE FROM user_templates WHERE id = ?").bind(templateId).run();
  
  return c.json({ success: true });
});

// Save sequence as template
app.post("/api/sequences/:id/save-template", authMiddleware, zValidator("json", CreateTemplateSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  const body = c.req.valid("json");
  const templateId = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Get sequence data
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  const blocks = await db.prepare("SELECT * FROM email_blocks WHERE sequence_id = ?").bind(sequenceId).all();
  const connections = await db.prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).all();
  
  const sequenceData = JSON.stringify({
    sequence,
    blocks: blocks.results,
    connections: connections.results
  });
  
  // Save to user_templates instead of sequence_templates for user's personal templates
  await db.prepare(`
    INSERT INTO user_templates (id, name, description, user_id, sequence_data, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(templateId, body.name, body.description || "", user.id, sequenceData, now, now).run();
  
  const template = await db.prepare("SELECT * FROM user_templates WHERE id = ?").bind(templateId).first();
  return c.json(template);
});

// ===== AI CONTENT GENERATION =====

// Generate AI content for email blocks (STATIC DATA - NO OPENAI)
app.post("/api/ai/generate-content", authMiddleware, zValidator("json", GenerateContentSchema), async (c) => {
  const user = c.get("user");
  const body = c.req.valid("json");

  console.log('[AI Generation] Request received:', { 
    userId: user?.id, 
    blockType: body.type, 
    tone: body.tone 
  });

  if (!user) {
    console.error('[AI Generation] No user found in request');
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Block configuration
  const blockConfig = {
    welcome: "welcome email that introduces new subscribers",
    "follow-up": "follow-up email that nurtures leads",
    offer: "promotional email with a special offer",
    reminder: "reminder email to encourage action",
    upsell: "upsell email to promote upgrades",
    "abandon-cart": "cart abandonment recovery email",
    reactivation: "re-engagement email for inactive subscribers"
  };

  // Generate static content based on block type and tone
  const staticContent = generateStaticContent(body.type, body.tone, body.custom_subject, body.custom_cta, body.answers);
  
  // No credits deducted for static data
  console.log('[AI Generation] Returning static content');

  return c.json({
    ...staticContent,
    credits_used: 0, // Static data is free
    word_count: 0
  });
});

// Helper function to generate static content
function generateStaticContent(
  blockType: string, 
  tone: string, 
  customSubject?: string, 
  customCTA?: string,
  answers?: Record<string, string>
): any {
  
  // Extract product/service info from answers if provided
  const productInfo = answers ? Object.values(answers).join(' ') : 'our product';
  
  const contentMap: Record<string, Record<string, any>> = {
    welcome: {
      friendly: {
        name: "Welcome to Our Community!",
        subject_line: customSubject || "🎉 Welcome! Let's get started together",
        preview_text: "We're thrilled to have you here!",
        body_copy: `Hi there!\n\nWelcome aboard! We're absolutely thrilled to have you join our community. ${productInfo}\n\nHere's what you can expect:\n• Exclusive tips and insights delivered to your inbox\n• Early access to new features and updates\n• A friendly team ready to help whenever you need us\n\nWe can't wait to see what you'll achieve with us. Let's make amazing things happen together!\n\nCheers,\nThe Team`,
        cta_text: customCTA || "Get Started Now",
        cta_url: "https://example.com/get-started"
      },
      professional: {
        name: "Welcome - Getting Started",
        subject_line: customSubject || "Welcome to [Company Name]",
        preview_text: "Your journey starts here",
        body_copy: `Dear Valued Customer,\n\nThank you for choosing our services. ${productInfo}\n\nWe are committed to providing you with exceptional value:\n• Professional support and guidance\n• Industry-leading solutions\n• Comprehensive resources at your fingertips\n\nOur team is here to ensure your success. We look forward to a productive partnership.\n\nBest regards,\nThe Team`,
        cta_text: customCTA || "Access Your Account",
        cta_url: "https://example.com/dashboard"
      },
      casual: {
        name: "Hey, Welcome!",
        subject_line: customSubject || "Hey! You're in 👋",
        preview_text: "Let's do this!",
        body_copy: `Hey!\n\nWelcome to the club! So glad you're here. ${productInfo}\n\nHere's the deal:\n• No fluff, just good stuff\n• We'll keep things simple and fun\n• Reach out anytime - we're real people!\n\nReady to dive in? Let's go!\n\nCatch you later,\nThe Team`,
        cta_text: customCTA || "Let's Go!",
        cta_url: "https://example.com/start"
      }
    },
    "follow-up": {
      friendly: {
        name: "Just Checking In!",
        subject_line: customSubject || "How's everything going? 👋",
        preview_text: "We'd love to hear from you!",
        body_copy: `Hi there!\n\nJust wanted to check in and see how things are going with ${productInfo}.\n\nHave you had a chance to:\n• Explore the main features?\n• Try out our tools?\n• Check out the resources we shared?\n\nIf you have any questions or need help with anything, just hit reply. We're here for you!\n\nLooking forward to hearing from you!\n\nWarm regards,\nThe Team`,
        cta_text: customCTA || "Share Your Feedback",
        cta_url: "https://example.com/feedback"
      },
      professional: {
        name: "Follow-Up: Next Steps",
        subject_line: customSubject || "Your next steps with us",
        preview_text: "Let's move forward together",
        body_copy: `Dear Customer,\n\nFollowing up on your recent engagement with ${productInfo}.\n\nWe recommend these next steps:\n• Review our comprehensive guide\n• Schedule a consultation with our team\n• Explore advanced features\n\nOur specialists are available to assist you in maximizing your investment.\n\nProfessionally,\nThe Team`,
        cta_text: customCTA || "Schedule Consultation",
        cta_url: "https://example.com/schedule"
      }
    },
    offer: {
      friendly: {
        name: "Special Offer Just for You!",
        subject_line: customSubject || "🎁 A special gift is waiting for you!",
        preview_text: "Don't miss out on this amazing deal!",
        body_copy: `Hi!\n\nWe've got something special for you! For a limited time, enjoy exclusive savings on ${productInfo}.\n\n✨ What you get:\n• Special discount just for you\n• Premium features included\n• No strings attached!\n\nThis offer won't last long, so grab it while you can!\n\nHappy shopping!\nThe Team`,
        cta_text: customCTA || "Claim Your Offer",
        cta_url: "https://example.com/offer"
      },
      persuasive: {
        name: "Limited Time Offer",
        subject_line: customSubject || "⚡ Don't miss out - Offer ends soon!",
        preview_text: "Your exclusive deal is here",
        body_copy: `You've been selected!\n\nThis is your chance to save big on ${productInfo}. But here's the catch - this exclusive offer expires in 48 hours.\n\n🔥 Why act now:\n• Lowest price we've ever offered\n• Limited spots available\n• Bonuses worth $500+ included\n\nThousands have already claimed theirs. Will you?\n\nAct fast,\nThe Team`,
        cta_text: customCTA || "Claim Discount Now",
        cta_url: "https://example.com/claim"
      }
    }
  };

  // Get content for block type and tone (fallback to friendly)
  const blockContent = contentMap[blockType] || contentMap.welcome;
  const toneContent = blockContent[tone] || blockContent.friendly || blockContent.professional;

  return toneContent;
}


// Rewrite email content with different tone (STATIC/DUMMY, NO OPENAI) 
app.post("/api/ai/rewrite-content", authMiddleware, async (c) => {
  const user = c.get("user");
  const body = await c.req.json();

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Return dummy rewritten content based on requested tone
  let { subject_line, preview_text, body_copy, cta_text, tone } = body;

  // Basic dummy transform per tone
  function applyTone(text: string, tone: string) {
    if (!text) return "";
    switch (tone) {
      case "friendly":
        return "😊 " + text;
      case "professional":
        return "Dear Customer, " + text;
      case "casual":
        return "Hey! " + text;
      case "persuasive":
        return text + " Don't miss out!";
      case "urgent":
        return "⏰ " + text + " Act now!";
      default:
        return text;
    }
  }

  return c.json({
    subject_line: applyTone(subject_line, tone),
    preview_text: applyTone(preview_text, tone),
    body_copy: applyTone(body_copy, tone),
    cta_text: applyTone(cta_text, tone),
    credits_used: 0,
    word_count: [subject_line, preview_text, body_copy, cta_text].join(" ").split(/\s+/).length,
  });
});


// ===== EXPORT ROUTES =====

// Export sequence
app.post("/api/sequences/:id/export", authMiddleware, zValidator("json", ExportSequenceSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  const body = c.req.valid("json");
  const exportId = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify sequence ownership
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  const blocks = await db.prepare("SELECT * FROM email_blocks WHERE sequence_id = ? ORDER BY send_delay_hours ASC").bind(sequenceId).all();
  const connections = await db.prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).all();
  
  // Track export
  await db.prepare(`
    INSERT INTO sequence_exports (id, sequence_id, user_id, export_type, export_format, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(exportId, sequenceId, user.id, body.format, body.format, now).run();
  
  let exportData;
  
  switch (body.format) {
    case 'csv':
      const csvHeaders = ['Email #', 'Type', 'Name', 'Subject Line', 'Preview Text', 'Email Body', 'Send Delay (Hours)', 'CTA Text', 'CTA URL'];
      const csvRows = (blocks.results as any[]).map((block, index) => [
        index + 1,
        block.type,
        block.name || '',
        block.subject_line || '',
        block.preview_text || '',
        block.body_copy || '',
        block.send_delay_hours || 0,
        block.cta_text || '',
        block.cta_url || ''
      ]);
      
      // Add UTF-8 BOM for proper Excel emoji rendering
      exportData = '\uFEFF' + [csvHeaders, ...csvRows].map(row => 
        row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
      ).join('\n');
      break;
      
    case 'txt':
      exportData = (blocks.results as any[]).map((block, index) => 
        `Email ${index + 1}: ${block.name}\n` +
        `Type: ${block.type}\n` +
        `Send Delay: ${block.send_delay_hours || 0} hours\n` +
        `Subject: ${block.subject_line || 'No subject'}\n` +
        `Preview: ${block.preview_text || 'No preview'}\n` +
        `Body: ${block.body_copy || 'No content'}\n` +
        `CTA: ${block.cta_text || 'No CTA'} (${block.cta_url || 'No URL'})\n` +
        `${'='.repeat(50)}\n`
      ).join('\n');
      break;
      
    case 'html':
      exportData = (blocks.results as any[]).map((block, index) => 
        `<div style="border: 1px solid #ddd; margin: 20px 0; padding: 20px; border-radius: 8px;">` +
        `<h3>Email ${index + 1}: ${block.name}</h3>` +
        `<p><strong>Type:</strong> ${block.type}</p>` +
        `<p><strong>Send Delay:</strong> ${block.send_delay_hours || 0} hours</p>` +
        `<p><strong>Subject:</strong> ${block.subject_line || 'No subject'}</p>` +
        `<p><strong>Preview:</strong> ${block.preview_text || 'No preview'}</p>` +
        `<div><strong>Body:</strong><br>${(block.body_copy || 'No content').replace(/\n/g, '<br>')}</div>` +
        `<p><strong>CTA:</strong> <a href="${block.cta_url || '#'}">${block.cta_text || 'No CTA'}</a></p>` +
        `</div>`
      ).join('');
      break;
      
    case 'json':
      exportData = JSON.stringify({
        sequence,
        blocks: blocks.results,
        connections: connections.results,
        exported_at: now
      }, null, 2);
      break;
      
    default:
      return c.json({ error: "Unsupported export format" }, 400);
  }
  
  return c.json({ 
    data: exportData,
    filename: `${String(sequence.name).replace(/[^a-zA-Z0-9]/g, '_')}_sequence.${body.format}`
  });
});

export default app;
