import express from 'express';
import crypto from 'crypto';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());

import dotenv from 'dotenv';
dotenv.config();

const CIPHER_SECRET = Buffer.from(process.env.CIPHER_SECRET, 'hex');

function encryptPayload(payload) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(CIPHER_SECRET, 'utf-8'),
    iv
  );
  const payloadStr = JSON.stringify(payload);
  const encrypted = Buffer.concat([cipher.update(payloadStr, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Token format: iv + tag + ciphertext (all base64url)
  return `${iv.toString('base64url')}.${tag.toString('base64url')}.${encrypted.toString('base64url')}`;
}

function decryptPayload(token) {
  try {
    const [ivB64, tagB64, encryptedB64] = token.split('.');
    const iv = Buffer.from(ivB64, 'base64url');
    const tag = Buffer.from(tagB64, 'base64url');
    const encrypted = Buffer.from(encryptedB64, 'base64url');

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      Buffer.from(CIPHER_SECRET, 'utf-8'),
      iv
    );
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return JSON.parse(decrypted.toString('utf-8'));
  } catch {
    return null;
  }
}

const codes = new Map();

app.get('/api/generateCode', (req, res) => {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const identifier = crypto
    .createHash('sha256')
    .update(code + Date.now().toString())
    .digest('hex')
    .slice(0, 12);
  const expiresAt = Date.now() + 2 * 60 * 1000;
  codes.set(identifier, { code, expiresAt, usedBy: null });
  res.json({ code, identifier, expiresAt });
});

app.get('/api/verifyCode', async (req, res) => {
  const { code, identifier } = req.query;
  if (!code || !identifier) return res.status(400).json({ error: 'Missing code or identifier' });

  const data = codes.get(identifier);
  if (!data || data.code !== code) return res.json({ status: 'unrecognised' });
  if (data.usedBy) return res.json({ status: 'used', usedBy: data.usedBy });
  if (Date.now() > data.expiresAt) return res.json({ status: 'unused', expiresAt: data.expiresAt });

  try {
    const projectUser = 'Swiftpixel';
    const projectId = '1161257744';
    const url = `https://api.scratch.mit.edu/users/${projectUser}/projects/${projectId}/comments`;

    const scratchRes = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; ScratchConnect/1.0)',
        'Accept': 'application/json',
      },
    });
    if (!scratchRes.ok) throw new Error('Scratch API error');

    const comments = await scratchRes.json();
    const twoMinutesAgo = Date.now() - 2 * 60 * 1000;

    let foundUser = null;
    for (const c of comments) {
      const commentTime = new Date(c.datetime_created).getTime();
      if (commentTime < twoMinutesAgo) continue;
      if (typeof c.content === 'string' && c.content.includes(code) && c.author?.username) {
        foundUser = c.author.username;
        break;
      }
    }

    if (foundUser) {
      data.usedBy = foundUser;

      const sessionToken = encryptPayload({
        username: foundUser,
        type: 'session',
        expiry: Date.now() + 32000 * 1000, // 60 minutes
      });
      const fastTrackToken = encryptPayload({
        username: foundUser,
        type: 'fast_track',
        expiry: Date.now() + 28 * 24 * 60 * 60 * 1000, // 28 days
      });

      return res.json({
        status: 'used',
        user: foundUser,
        token: sessionToken,
        fastTrackToken,
      });
    }

    return res.json({ status: 'unused', expiresAt: data.expiresAt });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.get('/api/verifyToken', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Missing token' });

  const payload = decryptPayload(token);
  if (!payload) return res.status(400).json({ error: 'Invalid token' });

  res.json({
    type: payload.type,
    username: payload.username,
    expiry: payload.expiry,
    expired: Date.now() > payload.expiry,
  });
});

app.listen(8080, () => {
  console.log('REST API server running on port 8080');
});