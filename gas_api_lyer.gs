// ============================================================
// United Security Group — GAS HTTP API Layer
// Drop this into code.gs — REPLACES the existing doGet / doPost
// All other functions (CRUD, auth, runProtected) stay untouched.
// ============================================================

// ── CORS helper ─────────────────────────────────────────────
function _corsHeaders() {
  // In production, replace '*' with your exact Vercel domain:
  // e.g. 'https://usg-hub.vercel.app'
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };
}

function _jsonResponse(obj, statusCode) {
  var payload = JSON.stringify(obj);
  var output  = ContentService.createTextOutput(payload)
                              .setMimeType(ContentService.MimeType.JSON);
  // GAS doesn't support custom HTTP status codes — always 200.
  // Errors are communicated via { success: false, error: '...' }
  return output;
}

// ── PUBLIC GET endpoints (no auth required) ─────────────────
//   GET ?action=health
//   GET ?action=publicJobs
function doGet(e) {
  var action = (e && e.parameter && e.parameter.action) || 'health';

  try {
    if (action === 'health') {
      return _jsonResponse({ success: true, status: 'ok', ts: new Date().toISOString() });
    }

    if (action === 'publicJobs') {
      return _jsonResponse(getPublicJobs());
    }

    return _jsonResponse({ success: false, error: 'Unknown GET action: ' + action });
  } catch (err) {
    return _jsonResponse({ success: false, error: err.message });
  }
}

// ── ALL authenticated + mutating calls come through POST ─────
//
// Expected JSON body:
// {
//   "action": "login" | "validateSession" | "logout" | "run",
//   // for action === "login":
//   "email": "...",
//   "password": "...",
//   // for action === "validateSession" | "logout":
//   "token": "...",
//   // for action === "run":
//   "token": "...",
//   "fn":    "addEmployee" | "updateEmployee" | ... (any key in runProtected),
//   "args":  [ ...positional args ]
// }
//
// Response always:
// { "success": boolean, "data"?: any, "error"?: string, ...extra }

function doPost(e) {
  var body;
  try {
    body = JSON.parse(e.postData.contents);
  } catch (parseErr) {
    return _jsonResponse({ success: false, error: 'Invalid JSON body' });
  }

  var action = String(body.action || '').trim();

  try {
    // ── Public auth actions (no token required) ──────────────

    if (action === 'login') {
      var result = loginUser(body.email, body.password);
      return _jsonResponse(result);
    }

    if (action === 'validateSession') {
      return _jsonResponse(validateSession(body.token));
    }

    if (action === 'logout') {
      return _jsonResponse(logoutUser(body.token));
    }

    // ── Public: job application portal ──────────────────────

    if (action === 'submitApplication') {
      return _jsonResponse(submitApplication(body.data || {}));
    }

    if (action === 'uploadCV') {
      return _jsonResponse(uploadCV(body.base64Data, body.fileName));
    }

    // ── All other actions require a valid token ──────────────

    if (action === 'run') {
      var token  = body.token;
      var fn     = body.fn;
      var args   = Array.isArray(body.args) ? body.args : [];

      if (!token) return _jsonResponse({ success: false, error: 'SESSION_EXPIRED' });
      if (!fn)    return _jsonResponse({ success: false, error: 'fn is required' });

      return _jsonResponse(runProtected(token, fn, args));
    }

    return _jsonResponse({ success: false, error: 'Unknown action: ' + action });

  } catch (err) {
    return _jsonResponse({ success: false, error: err.message });
  }
}
