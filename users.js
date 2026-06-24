// Tafoy CRM — admin user management (Vercel serverless function)
// Requires Vercel environment variables:
//   SUPABASE_URL                = https://bovhpvqtiocfhpzjgbab.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY   = (Supabase -> Settings -> API -> service_role secret)
//
// Endpoints (same origin as the dashboard):
//   GET    /api/users           -> list users (admin only)
//   POST   /api/users           -> { email, password, mode:'shared'|'private' } create user (admin only)
//   DELETE /api/users?id=<uuid> -> delete user (admin only)

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

function svcHeaders() {
  return {
    apikey: SERVICE_KEY,
    Authorization: 'Bearer ' + SERVICE_KEY,
    'Content-Type': 'application/json',
  };
}

async function getCaller(token) {
  try {
    const r = await fetch(SUPABASE_URL + '/auth/v1/user', {
      headers: { apikey: SERVICE_KEY, Authorization: 'Bearer ' + token },
    });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) {
    return null;
  }
}

async function readBody(req) {
  if (req.body) {
    return typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body;
  }
  return await new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch (e) { resolve({}); }
    });
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'authorization, content-type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!SUPABASE_URL || !SERVICE_KEY) {
    return res.status(500).json({ error: 'Server not configured: set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in Vercel.' });
  }

  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return res.status(401).json({ error: 'Not signed in.' });

  const caller = await getCaller(token);
  const callerRole = caller && caller.app_metadata && caller.app_metadata.role;
  if (!caller || callerRole !== 'admin') {
    return res.status(403).json({ error: 'Admins only.' });
  }

  if (req.method === 'GET') {
    try {
      const r = await fetch(SUPABASE_URL + '/auth/v1/admin/users?per_page=200', { headers: svcHeaders() });
      const d = await r.json();
      if (!r.ok) return res.status(400).json({ error: d.msg || 'Could not list users' });
      const users = (d.users || []).map((u) => ({
        id: u.id,
        email: u.email,
        role: (u.app_metadata || {}).role || 'agent',
        workspace: (u.app_metadata || {}).workspace || 'shared',
      }));
      return res.status(200).json({ users });
    } catch (e) {
      return res.status(500).json({ error: String(e) });
    }
  }

  if (req.method === 'POST') {
    try {
      const body = await readBody(req);
      const email = (body.email || '').trim();
      const password = body.password || '';
      const mode = body.mode === 'private' ? 'private' : 'shared';
      if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

      const createRes = await fetch(SUPABASE_URL + '/auth/v1/admin/users', {
        method: 'POST',
        headers: svcHeaders(),
        body: JSON.stringify({
          email,
          password,
          email_confirm: true,
          app_metadata: { role: 'agent', workspace: mode === 'private' ? 'pending' : 'shared' },
        }),
      });
      const created = await createRes.json();
      if (!createRes.ok) {
        return res.status(400).json({ error: created.msg || created.error_description || created.error || 'Could not create user' });
      }

      if (mode === 'private' && created.id) {
        await fetch(SUPABASE_URL + '/auth/v1/admin/users/' + created.id, {
          method: 'PUT',
          headers: svcHeaders(),
          body: JSON.stringify({ app_metadata: { role: 'agent', workspace: created.id } }),
        });
      }
      return res.status(200).json({ ok: true, email });
    } catch (e) {
      return res.status(500).json({ error: String(e) });
    }
  }

  if (req.method === 'DELETE') {
    try {
      const id = (req.query && req.query.id) || new URL(req.url, 'http://x').searchParams.get('id');
      if (!id) return res.status(400).json({ error: 'User id required.' });
      if (caller.id === id) return res.status(400).json({ error: 'You cannot remove yourself.' });
      const r = await fetch(SUPABASE_URL + '/auth/v1/admin/users/' + id, {
        method: 'DELETE',
        headers: svcHeaders(),
      });
      if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        return res.status(400).json({ error: e.msg || 'Could not delete user' });
      }
      return res.status(200).json({ ok: true });
    } catch (e) {
      return res.status(500).json({ error: String(e) });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
