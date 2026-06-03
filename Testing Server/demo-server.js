const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
const LOG_FILE = path.join(__dirname, 'server.log');

// ─── Valid credentials (for demo) ────────────────────────────────────────────
const VALID_USER = 'admin';
const VALID_PASS = 'admin123';

// ─── Logger ──────────────────────────────────────────────────────────────────
function writeLog(level, message, ip) {
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const line = `${now} ${level.padEnd(8)} ${message} from ${ip}\n`;
  fs.appendFileSync(LOG_FILE, line);
  console.log(line.trim());
}

// ─── Parse request body ──────────────────────────────────────────────────────
function getBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const params = new URLSearchParams(body);
        resolve({ username: params.get('username') || '', password: params.get('password') || '' });
      } catch {
        resolve({ username: '', password: '' });
      }
    });
  });
}

// ─── Get client IP ───────────────────────────────────────────────────────────
function getIP(req) {
  return req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
}

// ─── HTML Pages ──────────────────────────────────────────────────────────────
function loginPage(msg = '', msgType = '') {
  const alertBox = msg ? `
    <div class="alert ${msgType === 'error' ? 'alert-error' : 'alert-success'}">
      ${msgType === 'error' ? '✗' : '✓'} ${msg}
    </div>` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Demo Login Server</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0a0a0a;
    font-family: 'Courier New', monospace;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; color: #e5e5e5;
  }
  .card {
    background: #111;
    border: 1px solid #1f1f1f;
    border-top: 3px solid #e11d48;
    border-radius: 4px;
    padding: 40px;
    width: 100%;
    max-width: 400px;
    box-shadow: 0 0 40px rgba(225,29,72,0.1);
  }
  .logo {
    text-align: center;
    margin-bottom: 30px;
  }
  .logo-icon {
    font-size: 36px;
    display: block;
    margin-bottom: 8px;
  }
  .logo h1 {
    font-size: 18px;
    letter-spacing: 4px;
    text-transform: uppercase;
    color: #fff;
  }
  .logo p {
    font-size: 11px;
    color: #555;
    margin-top: 4px;
    letter-spacing: 2px;
  }
  label {
    display: block;
    font-size: 11px;
    letter-spacing: 2px;
    color: #666;
    text-transform: uppercase;
    margin-bottom: 6px;
    margin-top: 18px;
  }
  input {
    width: 100%;
    background: #0a0a0a;
    border: 1px solid #222;
    color: #e5e5e5;
    padding: 10px 14px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 14px;
    outline: none;
    transition: border-color .2s;
  }
  input:focus { border-color: #9f1239; }
  button {
    width: 100%;
    margin-top: 24px;
    background: #9f1239;
    color: #fff;
    border: none;
    padding: 12px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 14px;
    letter-spacing: 3px;
    text-transform: uppercase;
    cursor: pointer;
    transition: background .2s;
  }
  button:hover { background: #e11d48; }
  .alert {
    padding: 10px 14px;
    border-radius: 3px;
    font-size: 13px;
    margin-bottom: 20px;
  }
  .alert-error   { background: #1a0008; border: 1px solid #9f1239; color: #fb7185; }
  .alert-success { background: #001a08; border: 1px solid #166534; color: #4ade80; }
  .hint {
    margin-top: 20px;
    padding: 10px;
    background: #0d0d0d;
    border: 1px solid #1a1a1a;
    border-radius: 3px;
    font-size: 11px;
    color: #444;
    text-align: center;
    line-height: 1.8;
  }
  .hint span { color: #666; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <span class="logo-icon">⬡</span>
    <h1>Secure Server</h1>
    <p>Authentication Required</p>
  </div>

  ${alertBox}

  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" placeholder="Enter username" autocomplete="off">
    <label>Password</label>
    <input type="password" name="password" placeholder="Enter password">
    <button type="submit">Login →</button>
  </form>

  <div class="hint">
    Demo credentials<br>
    <span>user: admin &nbsp;|&nbsp; pass: admin123</span>
  </div>
</div>
</body>
</html>`;
}

function dashboardPage(username) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0a0a0a;
    font-family: 'Courier New', monospace;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; color: #e5e5e5;
  }
  .card {
    background: #111;
    border: 1px solid #1f1f1f;
    border-top: 3px solid #22c55e;
    border-radius: 4px;
    padding: 40px;
    width: 100%;
    max-width: 420px;
    box-shadow: 0 0 40px rgba(34,197,94,0.08);
    text-align: center;
  }
  .icon { font-size: 48px; margin-bottom: 16px; }
  h2 { font-size: 20px; color: #fff; letter-spacing: 2px; margin-bottom: 8px; }
  p { font-size: 13px; color: #555; margin-bottom: 24px; }
  .user-box {
    background: #0a0a0a;
    border: 1px solid #1a1a1a;
    border-radius: 3px;
    padding: 12px;
    font-size: 14px;
    color: #22c55e;
    margin-bottom: 24px;
    letter-spacing: 1px;
  }
  a {
    display: inline-block;
    background: #1a1a1a;
    color: #888;
    padding: 10px 24px;
    border-radius: 3px;
    text-decoration: none;
    font-size: 12px;
    letter-spacing: 2px;
    text-transform: uppercase;
    transition: background .2s;
  }
  a:hover { background: #222; color: #e5e5e5; }
</style>
</head>
<body>
<div class="card">
  <div class="icon">✓</div>
  <h2>Access Granted</h2>
  <p>You have successfully authenticated.</p>
  <div class="user-box">Logged in as: ${username}</div>
  <a href="/logout">Logout</a>
</div>
</body>
</html>`;
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const ip = getIP(req);
  const url = req.url;
  const method = req.method;

  // GET / → show login page
  if (method === 'GET' && url === '/') {
    writeLog('INFO', 'Login page accessed', ip);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(loginPage());
    return;
  }

  // POST /login → process credentials
  if (method === 'POST' && url === '/login') {
    const { username, password } = await getBody(req);

    if (username === VALID_USER && password === VALID_PASS) {
      // ✓ Correct credentials
      writeLog('INFO', `Accepted password for user [${username}]`, ip);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(dashboardPage(username));
    } else {
      // ✗ Wrong credentials
      writeLog('ERROR', `Failed password for user [${username || 'unknown'}] - Invalid credentials`, ip);
      res.writeHead(401, { 'Content-Type': 'text/html' });
      res.end(loginPage('Invalid username or password. Try again.', 'error'));
    }
    return;
  }

  // GET /logout
  if (method === 'GET' && url === '/logout') {
    writeLog('INFO', 'User session ended - logout', ip);
    res.writeHead(302, { Location: '/' });
    res.end();
    return;
  }

  // 404
  res.writeHead(404);
  res.end('Not found');
});

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  writeLog('INFO', `Demo server started on port ${PORT}`, '127.0.0.1');
  console.log(`\n  Open → http://localhost:${PORT}\n`);
});