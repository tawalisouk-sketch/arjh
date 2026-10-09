/**
 * Sha'ah — Serveur v2
 * -----------------------------------------------------------
 * Aucune dépendance externe : uniquement les modules intégrés à Node.js (18+).
 *
 * Pointage : QR dynamique (25 s) affiché par la tablette + signature HMAC
 * faite par le téléphone personnel de l'employé (app Scan).
 *
 * Nouveautés v2 :
 *  - Heures supplémentaires calculées au pointage de départ.
 *  - Module congés : l'employé passe "En congé" (inactif) jusqu'à sa date de
 *    retour, puis redevient actif automatiquement.
 *  - Clôture automatique de la journée : tout employé actif qui n'a pas pointé
 *    du tout un jour travaillé est marqué absent.
 *  - Justifications envoyées par l'employé = "en attente". Seul le RH accepte
 *    (retard/absence non comptabilisé) ou refuse (comptabilisé).
 *
 * Variables d'environnement (toutes optionnelles) :
 *   PORT          Port d'écoute
 *   DATA_FILE     Chemin du fichier de données (ex : /data/data.json sur un disque persistant)
 *   TIMEZONE      Fuseau horaire de l'entreprise (défaut : Africa/Abidjan)
 *   TRUST_PROXY   1 = l'application est derrière un proxy (Render, Railway…) :
 *                 l'adresse IP réelle est lue dans X-Forwarded-For.
 *                 Activé automatiquement sur Render et Railway.
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_FILE = path.resolve(process.env.DATA_FILE || path.join(ROOT, 'data.json'));
const DATA_DIR = path.dirname(DATA_FILE);
const BACKUP_DIR = path.join(DATA_DIR, 'sauvegardes');
const PIECES_DIR = path.join(DATA_DIR, 'justificatifs');
const CHALLENGE_TTL_MS = 25 * 1000;
const SIGNED_MAX_SKEW_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_PIECE_BYTES = 1.5 * 1024 * 1024;
const TRUST_PROXY = process.env.TRUST_PROXY === '1' ||
  (process.env.TRUST_PROXY !== '0' && !!(process.env.RENDER || process.env.RAILWAY_ENVIRONMENT));

let TZ = process.env.TIMEZONE || 'Africa/Abidjan';
try { new Intl.DateTimeFormat('fr', { timeZone: TZ }); }
catch (e) { console.error('Fuseau horaire invalide (' + TZ + '), utilisation de UTC.'); TZ = 'UTC'; }

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json'
};

// ============================================================
// DATES & HEURES (toujours dans le fuseau de l'entreprise)
// ============================================================
const FMT = new Intl.DateTimeFormat('en-CA', {
  timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
});
function nowLocal(d = new Date()) {
  const p = {};
  FMT.formatToParts(d).forEach(x => { p[x.type] = x.value; });
  const hh = Number(p.hour) % 24, mm = Number(p.minute), ss = Number(p.second);
  return {
    date: `${p.year}-${p.month}-${p.day}`,
    time: String(hh).padStart(2, '0') + ':' + p.minute,
    minutes: hh * 60 + mm, seconds: hh * 3600 + mm * 60 + ss, ts: d.getTime()
  };
}
function isDate(s) { return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + 'T00:00:00Z')); }
function isTime(s) { return typeof s === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(s); }
function toMin(t) { const [h, m] = t.split(':').map(Number); return h * 60 + m; }
function addDays(s, n) { const d = new Date(s + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); }
function weekday(s) { return new Date(s + 'T00:00:00Z').getUTCDay(); }

// ============================================================
// SÉCURITÉ
// ============================================================
const makeSalt = () => crypto.randomBytes(16).toString('hex');
const hashPassword = (pwd, salt) => crypto.scryptSync(String(pwd), salt, 64).toString('hex');
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const hmac = (secret, msg) => crypto.createHmac('sha256', String(secret)).update(String(msg)).digest('hex');
function safeEqual(a, b) {
  const ba = Buffer.from(String(a)), bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
function randomCode(len, chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789') {
  let s = ''; for (let i = 0; i < len; i++) s += chars[crypto.randomInt(chars.length)]; return s;
}
const randomPassword = () => randomCode(12, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789');

// Sessions RH (mémoire)
const sessions = new Map();
function createSession(username) {
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { username, expires: Date.now() + SESSION_TTL_MS });
  return sid;
}
function getSession(sid) {
  const s = sid && sessions.get(sid);
  if (!s) return null;
  if (Date.now() > s.expires) { sessions.delete(sid); return null; }
  return s;
}

// Limitation des échecs (anti force brute) — seuls les échecs sont comptés
const fails = new Map();
function isBlocked(key, max) { const r = fails.get(key); return !!(r && Date.now() < r.resetAt && r.count >= max); }
function addFail(key, windowMs = 15 * 60 * 1000) {
  const now = Date.now(); const r = fails.get(key);
  if (!r || now > r.resetAt) fails.set(key, { count: 1, resetAt: now + windowMs }); else r.count++;
}
const clearFails = (key) => fails.delete(key);

// Challenges QR (mémoire)
const challenges = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now > s.expires) sessions.delete(k);
  for (const [k, r] of fails) if (now > r.resetAt) fails.delete(k);
  for (const [k, c] of challenges) if (now > c.expiresAt + 60 * 1000) challenges.delete(k);
}, 60 * 1000).unref();

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'inconnu';
}

// ============================================================
// DONNÉES (en mémoire, écrites sur disque à chaque modification)
// ============================================================
let DB = null;

function newJustif(statut = 'aucune', extra = {}) { return Object.assign({ statut, motif: '' }, extra); }

function load() {
  let d = null;
  try { d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (e) {
    if (fs.existsSync(DATA_FILE)) {
      // Fichier corrompu : on le met de côté au lieu de l'écraser
      const bad = DATA_FILE + '.corrompu-' + Date.now();
      fs.copyFileSync(DATA_FILE, bad);
      console.error('ATTENTION : data.json illisible, copie conservée dans ' + bad + '. Restaurez une sauvegarde de ' + BACKUP_DIR);
      process.exit(1);
    }
    d = {};
  }
  migrate(d);
  DB = d;
  save();
}

function printCredentials(title, user, pwd, kiosk) {
  console.log('\n======================================================');
  console.log(' ' + title);
  console.log('   Utilisateur RH               : ' + user);
  console.log('   Mot de passe RH              : ' + pwd);
  console.log('   Code d\'activation tablette   : ' + kiosk);
  console.log(' -> Notez-les, puis changez le mot de passe dans');
  console.log('    Espace RH > Paramètres.');
  console.log('======================================================\n');
}

function migrate(d) {
  const today = nowLocal().date;
  d.version = 2;
  if (!d.settings) d.settings = {};
  const s = d.settings;
  if (!s.kioskToken) s.kioskToken = randomCode(8);
  if (!s.rhPasswordHash) {
    const pwd = randomPassword();
    s.rhUsername = s.rhUsername || 'admin';
    s.rhPasswordSalt = makeSalt();
    s.rhPasswordHash = hashPassword(pwd, s.rhPasswordSalt);
    delete s.pin;
    printCredentials('Identifiants générés (première installation) :', s.rhUsername, pwd, s.kioskToken);
  }
  if (!isTime(s.heureCloture)) s.heureCloture = '20:00';
  if (!Array.isArray(s.joursTravailles)) s.joursTravailles = [1, 2, 3, 4, 5];
  if (!Array.isArray(s.joursFeries)) s.joursFeries = [];
  if (!isDate(s.dernierJourCloture)) s.dernierJourCloture = addDays(today, -1); // pas de rattrapage historique

  ['employes', 'pointages', 'absences', 'conges'].forEach(k => { if (!Array.isArray(d[k])) d[k] = []; });
  if (typeof d.lid !== 'number') d.lid = 0;

  d.employes.forEach(e => {
    delete e.faceDescriptor;
    if (!isTime(e.href)) e.href = '08:00';
    if (!isTime(e.hdep)) e.hdep = '17:30';
    if (e.statut !== 'Inactif') e.statut = 'Actif';
    if (!isDate(e.dateEntree)) e.dateEntree = today;
    if (e.secret !== undefined) {
      // v1 : le même code servait au jumelage ET à la signature.
      if (e.phonePaired) e.deviceSecret = e.secret; else e.pairCodeHash = sha256(String(e.secret).toUpperCase());
      delete e.secret;
    }
    e.phonePaired = !!(e.phonePaired && e.deviceSecret);
    if (!e.deviceSecret) e.deviceSecret = null;
    if (!e.pairCodeHash) e.pairCodeHash = null;
  });

  // v1 -> v2 : "retards" devient "pointages" (arrivées + départs)
  if (Array.isArray(d.retards)) {
    d.retards.forEach(r => {
      const ecart = Math.max(0, Number(r.totalMn) || 0);
      let justif = newJustif();
      if (ecart > 0) {
        if (r.justifie === 'Oui' && r.source === 'rh') justif = newJustif('acceptee', { motif: r.motif || '', decisionTs: r.ts || Date.now(), decisionPar: 'migration' });
        else if (r.motif) justif = newJustif('en_attente', { motif: r.motif, demandeTs: r.ts || Date.now() });
      }
      d.pointages.push({
        id: r.id || ('I' + (++d.lid)), empId: r.empId, empNom: r.empNom, date: r.date,
        type: r.type === 'depart' ? 'depart' : 'arrivee', heure: r.harr || '', hprev: r.hprev || '',
        ecartMn: ecart, supMn: 0, source: r.source === 'rh' ? 'rh' : 'scan', justif, ts: r.ts || Date.now()
      });
    });
    delete d.retards;
  }
  d.absences.forEach(a => {
    if (!a.justif) {
      a.justif = a.justifie === 'Oui'
        ? newJustif('acceptee', { motif: a.motif || '', decisionTs: a.ts || Date.now(), decisionPar: 'migration' })
        : newJustif('aucune', { motif: '' });
      delete a.justifie;
    }
    if (!a.source) a.source = 'rh';
    if (!a.dateFin) a.dateFin = a.dateDebut;
  });
}

let lastBackupDay = null;
function backupIfNeeded() {
  try {
    const day = nowLocal().date;
    if (lastBackupDay === day || !fs.existsSync(DATA_FILE)) return;
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const dest = path.join(BACKUP_DIR, `data-${day}.json`);
    if (!fs.existsSync(dest)) fs.copyFileSync(DATA_FILE, dest);
    lastBackupDay = day;
    // On garde les 60 dernières sauvegardes
    const files = fs.readdirSync(BACKUP_DIR).filter(f => /^data-\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort();
    files.slice(0, Math.max(0, files.length - 60)).forEach(f => fs.unlinkSync(path.join(BACKUP_DIR, f)));
  } catch (e) { console.error('Sauvegarde automatique impossible :', e.message); }
}

function save() {
  backupIfNeeded();
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(DB));
  fs.renameSync(tmp, DATA_FILE);
}

const nid = (prefix = 'I') => prefix + (++DB.lid);
const findEmp = (id) => DB.employes.find(e => e.id === id);

// ============================================================
// RÈGLES MÉTIER
// ============================================================
function congeEnCours(empId, date) {
  return DB.conges.find(c => c.empId === empId && c.dateDebut <= date && date < c.dateRetour) || null;
}
// Statut effectif : Inactif (manuel) > En congé (automatique) > Actif
function statutEffectif(emp, date) {
  if (emp.statut === 'Inactif') return 'Inactif';
  if (congeEnCours(emp.id, date)) return 'En congé';
  return 'Actif';
}
function isJourTravaille(date) {
  return DB.settings.joursTravailles.includes(weekday(date)) && !DB.settings.joursFeries.includes(date);
}
function joursOuvres(deb, fin) {
  let n = 0, d = deb, guard = 0;
  while (d <= fin && guard++ < 800) { if (isJourTravaille(d)) n++; d = addDays(d, 1); }
  return n;
}
function absenceCouvre(empId, date) {
  return DB.absences.some(a => a.empId === empId && a.dateDebut <= date && date <= a.dateFin);
}
// Supprime les absences automatiques d'un employé sur une période (pointage manuel, congé saisi après coup)
function retirerAbsencesAuto(empId, deb, finIncl) {
  DB.absences = DB.absences.filter(a => !(a.empId === empId && a.source === 'auto' && a.dateDebut >= deb && a.dateDebut <= finIncl));
}

// Calcule retard / départ anticipé / heures supplémentaires
function calculEcarts(type, heure, hprev) {
  const diff = toMin(heure) - toMin(hprev);
  if (type === 'arrivee') return { ecartMn: Math.max(0, diff), supMn: 0 };
  return { ecartMn: Math.max(0, -diff), supMn: Math.max(0, diff) };
}

function enregistrerPointage(emp, type) {
  const now = nowLocal();
  const deja = DB.pointages.find(p => p.empId === emp.id && p.date === now.date && p.type === type);
  if (deja) return { ok: false, error: 'Déjà pointé aujourd\'hui à ' + deja.heure, already: { heure: deja.heure } };
  const hprev = type === 'depart' ? emp.hdep : emp.href;
  const { ecartMn, supMn } = calculEcarts(type, now.time, hprev);
  const rec = {
    id: nid(), empId: emp.id, empNom: emp.nom, date: now.date, type, heure: now.time, hprev,
    ecartMn, supMn, source: 'scan', justif: newJustif(), ts: Date.now()
  };
  DB.pointages.push(rec);
  retirerAbsencesAuto(emp.id, now.date, now.date);
  save();
  return { ok: true, record: { type, date: rec.date, heure: rec.heure, hprev, ecartMn, supMn } };
}

// Clôture d'une journée : absent si aucun pointage
function cloturerJour(date) {
  if (!isJourTravaille(date)) return 0;
  let n = 0;
  DB.employes.forEach(e => {
    if (e.statut !== 'Actif' || e.dateEntree > date) return;
    if (congeEnCours(e.id, date)) return;
    if (DB.pointages.some(p => p.empId === e.id && p.date === date)) return;
    if (absenceCouvre(e.id, date)) return;
    DB.absences.push({
      id: nid(), empId: e.id, empNom: e.nom, dateDebut: date, dateFin: date, jours: 1,
      motif: 'Aucun pointage ce jour', source: 'auto', justif: newJustif(), ts: Date.now()
    });
    n++;
  });
  return n;
}
function tickCloture() {
  try {
    const now = nowLocal();
    const s = DB.settings;
    const jusqua = now.minutes >= toMin(s.heureCloture) ? now.date : addDays(now.date, -1);
    let d = addDays(s.dernierJourCloture, 1), guard = 0, total = 0, changed = false;
    while (d <= jusqua && guard++ < 62) {
      total += cloturerJour(d);
      s.dernierJourCloture = d; changed = true;
      d = addDays(d, 1);
    }
    if (changed) { save(); if (total) console.log(`Clôture jusqu'au ${s.dernierJourCloture} : ${total} absence(s) automatique(s).`); }
  } catch (e) { console.error('Clôture automatique : erreur', e); }
}

// ============================================================
// VUES
// ============================================================
function vueEmploye(e, date) {
  const c = congeEnCours(e.id, date);
  return {
    id: e.id, nom: e.nom, poste: e.poste || '', dept: e.dept || '', href: e.href, hdep: e.hdep,
    statut: e.statut, dateEntree: e.dateEntree, phonePaired: !!e.phonePaired, codeEnAttente: !!e.pairCodeHash,
    statutEffectif: statutEffectif(e, date), retourConge: c ? c.dateRetour : null
  };
}
function etatRH() {
  const now = nowLocal();
  const s = DB.settings;
  return {
    ok: true,
    serveur: { date: now.date, time: now.time, ts: now.ts, jourTravaille: isJourTravaille(now.date), timezone: TZ },
    employes: DB.employes.map(e => vueEmploye(e, now.date)),
    pointages: DB.pointages, absences: DB.absences, conges: DB.conges,
    settings: {
      rhUsername: s.rhUsername, kioskToken: s.kioskToken, heureCloture: s.heureCloture,
      joursTravailles: s.joursTravailles, joursFeries: s.joursFeries, dernierJourCloture: s.dernierJourCloture
    }
  };
}

// ============================================================
// HTTP
// ============================================================
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(self), microphone=(), geolocation=()'
};
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

function sendJSON(res, status, obj, extra = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  }, SEC_HEADERS, extra));
  res.end(body);
}
const fail = (res, status, error, extra) => sendJSON(res, status, Object.assign({ ok: false, error }, extra || {}));

function readBody(req, maxBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0, done = false;
    req.on('data', (c) => {
      if (done) return;
      size += c.length;
      if (size > maxBytes) { done = true; reject(new Error('PAYLOAD_TOO_LARGE')); req.resume(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (done) return;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try { const v = JSON.parse(raw); resolve(v && typeof v === 'object' ? v : {}); }
      catch (e) { reject(new Error('INVALID_JSON')); }
    });
    req.on('error', reject);
  });
}

function serveStatic(req, res, urlPath) {
  const rel = urlPath === '/' ? '/index.html' : urlPath;
  if (rel.includes('\0')) { res.writeHead(400); return res.end(); }
  const filePath = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end('Interdit'); }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, Object.assign({ 'Content-Type': 'text/plain; charset=utf-8' }, SEC_HEADERS)); return res.end('Page introuvable'); }
    const ext = path.extname(filePath).toLowerCase();
    const headers = Object.assign({ 'Content-Type': MIME[ext] || 'application/octet-stream' }, SEC_HEADERS);
    if (ext === '.html') { headers['Content-Security-Policy'] = CSP; headers['Cache-Control'] = 'no-cache'; }
    res.writeHead(200, headers);
    res.end(data);
  });
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('='); if (i < 0) return;
    try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch (e) { /* ignoré */ }
  });
  return out;
}
function isHttps(req) { return req.socket.encrypted || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https'); }
function sessionCookie(req, sid, maxAge) {
  return `sid=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}` + (isHttps(req) ? '; Secure' : '');
}

const str = (v, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const JUSTIF_STATUTS = ['aucune', 'en_attente', 'acceptee', 'refusee'];

// ============================================================
// ROUTES
// ============================================================
async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  let p;
  try { p = decodeURIComponent(url.pathname); } catch (e) { return fail(res, 400, 'Adresse invalide'); }
  const M = req.method;
  const ip = clientIp(req);

  if (!p.startsWith('/api/')) {
    if (M === 'GET' || M === 'HEAD') return serveStatic(req, res, p);
    res.writeHead(405); return res.end();
  }

  // Protection CSRF : toute requête qui modifie quelque chose doit être en JSON
  if (M !== 'GET' && !(req.headers['content-type'] || '').includes('application/json')) {
    return fail(res, 415, 'Format de requête non accepté');
  }

  // ---------- HEURE DU SERVEUR (publique) ----------
  if (p === '/api/time' && M === 'GET') {
    const n = nowLocal();
    return sendJSON(res, 200, { ok: true, date: n.date, time: n.time, seconds: n.seconds, ts: n.ts });
  }

  // ---------- CONNEXION RH ----------
  if (p === '/api/login' && M === 'POST') {
    const key = 'login:' + ip;
    if (isBlocked(key, 8)) return fail(res, 429, 'Trop de tentatives. Réessayez dans 15 minutes.');
    const b = await readBody(req);
    const s = DB.settings;
    const userOk = safeEqual(str(b.username, 100), s.rhUsername);
    const passOk = safeEqual(hashPassword(typeof b.password === 'string' ? b.password : '', s.rhPasswordSalt), s.rhPasswordHash);
    if (!userOk || !passOk) { addFail(key); return fail(res, 401, 'Identifiant ou mot de passe incorrect'); }
    clearFails(key);
    const sid = createSession(s.rhUsername);
    return sendJSON(res, 200, { ok: true, username: s.rhUsername }, { 'Set-Cookie': sessionCookie(req, sid, SESSION_TTL_MS / 1000) });
  }
  if (p === '/api/logout' && M === 'POST') {
    const sid = parseCookies(req).sid; if (sid) sessions.delete(sid);
    return sendJSON(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, '', 0) });
  }
  if (p === '/api/session' && M === 'GET') {
    const s = getSession(parseCookies(req).sid);
    return sendJSON(res, 200, s ? { ok: true, loggedIn: true, username: s.username } : { ok: true, loggedIn: false });
  }

  // ---------- TABLETTE ----------
  if (p.startsWith('/api/kiosk/') || p.startsWith('/api/pointage/challenge')) {
    const key = 'kiosk:' + ip;
    if (isBlocked(key, 10)) return fail(res, 429, 'Trop de tentatives. Réessayez dans 15 minutes.');
    const token = String(req.headers['x-kiosk-token'] || '').toUpperCase();
    if (!token || !safeEqual(token, DB.settings.kioskToken)) { addFail(key); return fail(res, 401, 'Tablette non activée'); }
    clearFails(key);
    return routesKiosk(req, res, p, M);
  }

  // ---------- TÉLÉPHONE (app Scan) ----------
  if (p === '/api/employee/pair' && M === 'POST') {
    const key = 'pair:' + ip;
    if (isBlocked(key, 10)) return fail(res, 429, 'Trop de tentatives. Réessayez dans 15 minutes.');
    const b = await readBody(req);
    const code = str(b.code || b.secret, 32).toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!code) return fail(res, 400, 'Code requis');
    const h = sha256(code);
    const emp = DB.employes.find(e => e.statut === 'Actif' && e.pairCodeHash && safeEqual(e.pairCodeHash, h));
    if (!emp) { addFail(key); return fail(res, 401, 'Code incorrect ou déjà utilisé. Demandez un nouveau code au service RH.'); }
    clearFails(key);
    emp.deviceSecret = crypto.randomBytes(32).toString('hex'); // clé de signature propre au téléphone
    emp.pairCodeHash = null;                                    // le code ne sert qu'une fois
    emp.phonePaired = true;
    save();
    return sendJSON(res, 200, { ok: true, empId: emp.id, empNom: emp.nom, secret: emp.deviceSecret });
  }

  if (p === '/api/pointage/scan' && M === 'POST') {
    const key = 'scan:' + ip;
    if (isBlocked(key, 20)) return fail(res, 429, 'Trop de tentatives. Patientez quelques minutes.');
    const b = await readBody(req);
    const challengeId = str(b.challengeId, 64), empId = str(b.empId, 32), signature = str(b.signature, 128);
    if (!challengeId || !empId || !signature) return fail(res, 400, 'Requête invalide');
    const c = challenges.get(challengeId);
    if (!c) { addFail(key, 5 * 60 * 1000); return fail(res, 404, 'Ce QR est introuvable ou a expiré.'); }
    if (Date.now() > c.expiresAt) { c.status = 'expired'; return fail(res, 410, 'Ce QR a expiré. Recommencez sur la tablette.'); }
    if (c.status !== 'pending') return fail(res, 409, 'Ce QR a déjà été utilisé.');
    if (c.empId !== empId) { addFail(key, 5 * 60 * 1000); return fail(res, 403, 'Ce QR a été demandé pour une autre personne.'); }
    const emp = findEmp(empId);
    if (!emp || !emp.deviceSecret) return fail(res, 403, 'Téléphone non jumelé. Demandez un nouveau code au service RH.', { code: 'NOT_PAIRED' });
    if (!safeEqual(signature, hmac(emp.deviceSecret, challengeId))) {
      addFail(key, 5 * 60 * 1000);
      return fail(res, 403, 'Signature invalide : ce téléphone n\'est plus jumelé.', { code: 'NOT_PAIRED' });
    }
    const today = nowLocal().date;
    if (statutEffectif(emp, today) !== 'Actif') return fail(res, 403, 'Employé inactif ou en congé.');
    const r = enregistrerPointage(emp, c.type);
    if (!r.ok) { c.status = 'rejected'; c.error = r.error; return fail(res, 409, r.error); }
    c.status = 'confirmed'; c.record = r.record;
    return sendJSON(res, 200, { ok: true, empNom: emp.nom, record: r.record });
  }

  if (p === '/api/employee/requete' && M === 'POST') {
    const key = 'sig:' + ip;
    if (isBlocked(key, 20)) return fail(res, 429, 'Trop de tentatives. Patientez quelques minutes.');
    const b = await readBody(req, 3 * 1024 * 1024);
    if (typeof b.payload !== 'string' || typeof b.signature !== 'string') return fail(res, 400, 'Requête invalide');
    let q; try { q = JSON.parse(b.payload); } catch (e) { return fail(res, 400, 'Requête invalide'); }
    const emp = q && typeof q.empId === 'string' ? findEmp(q.empId) : null;
    if (!emp || !emp.deviceSecret) return fail(res, 403, 'Téléphone non jumelé.', { code: 'NOT_PAIRED' });
    if (!safeEqual(b.signature, hmac(emp.deviceSecret, b.payload))) { addFail(key, 5 * 60 * 1000); return fail(res, 403, 'Signature invalide.', { code: 'NOT_PAIRED' }); }
    if (typeof q.ts !== 'number' || Math.abs(Date.now() - q.ts) > SIGNED_MAX_SKEW_MS) return fail(res, 400, 'Heure du téléphone incorrecte. Réessayez.');
    return routesEmploye(res, emp, q);
  }

  // ---------- RH (authentifié) ----------
  const session = getSession(parseCookies(req).sid);
  if (!session) return fail(res, 401, 'Non authentifié');
  return routesRH(req, res, p, M, session);
}

// ---------- Tablette ----------
async function routesKiosk(req, res, p, M) {
  const today = nowLocal().date;
  if (p === '/api/kiosk/employes' && M === 'GET') {
    const list = DB.employes.filter(e => statutEffectif(e, today) === 'Actif')
      .map(e => ({ id: e.id, nom: e.nom, href: e.href, hdep: e.hdep, paire: !!e.phonePaired }))
      .sort((a, b) => a.nom.localeCompare(b.nom, 'fr'));
    return sendJSON(res, 200, { ok: true, employes: list });
  }
  if (p === '/api/pointage/challenge' && M === 'POST') {
    const b = await readBody(req);
    const type = b.type === 'depart' ? 'depart' : (b.type === 'arrivee' ? 'arrivee' : null);
    const emp = findEmp(str(b.empId, 32));
    if (!emp || !type) return fail(res, 400, 'Requête invalide');
    if (statutEffectif(emp, today) !== 'Actif') return fail(res, 403, 'Employé inactif ou en congé.');
    if (!emp.phonePaired) return fail(res, 409, 'Téléphone non jumelé : demandez votre code au service RH.');
    const deja = DB.pointages.find(x => x.empId === emp.id && x.date === today && x.type === type);
    if (deja) return fail(res, 409, 'Déjà pointé aujourd\'hui à ' + deja.heure, { already: { heure: deja.heure } });
    for (const [k, c] of challenges) if (c.empId === emp.id && c.status === 'pending') challenges.delete(k); // un seul QR actif par employé
    const id = crypto.randomBytes(9).toString('hex');
    challenges.set(id, { id, empId: emp.id, type, expiresAt: Date.now() + CHALLENGE_TTL_MS, status: 'pending', record: null, error: null });
    return sendJSON(res, 200, { ok: true, challengeId: id, expiresIn: CHALLENGE_TTL_MS / 1000 });
  }
  const m = p.match(/^\/api\/pointage\/challenge\/([a-f0-9]{18})$/);
  if (m && M === 'GET') {
    const c = challenges.get(m[1]);
    if (!c) return sendJSON(res, 200, { ok: true, status: 'expired' });
    if (c.status === 'pending' && Date.now() > c.expiresAt) c.status = 'expired';
    return sendJSON(res, 200, { ok: true, status: c.status, record: c.record, error: c.error });
  }
  return fail(res, 404, 'Route inconnue');
}

// ---------- Téléphone (requêtes signées) ----------
function vueJustif(j) { return { statut: j.statut, motif: j.motif || '', commentaire: j.commentaire || '', piece: !!j.piece }; }

function routesEmploye(res, emp, q) {
  const today = nowLocal().date;
  const limite = addDays(today, -60);
  if (q.action === 'profil') {
    return sendJSON(res, 200, { ok: true, empNom: emp.nom, statut: statutEffectif(emp, today) });
  }
  if (q.action === 'historique') {
    const pointages = DB.pointages.filter(x => x.empId === emp.id && x.date >= limite && (x.ecartMn > 0 || x.supMn > 0))
      .map(x => ({ id: x.id, kind: 'pointage', type: x.type, date: x.date, heure: x.heure, hprev: x.hprev, ecartMn: x.ecartMn, supMn: x.supMn, justif: vueJustif(x.justif) }));
    const absences = DB.absences.filter(a => a.empId === emp.id && a.dateFin >= limite)
      .map(a => ({ id: a.id, kind: 'absence', dateDebut: a.dateDebut, dateFin: a.dateFin, jours: a.jours, motif: a.motif, source: a.source, justif: vueJustif(a.justif) }));
    return sendJSON(res, 200, { ok: true, pointages, absences });
  }
  if (q.action === 'justifier') {
    const kind = q.kind === 'absence' ? 'absence' : 'pointage';
    const rec = (kind === 'absence' ? DB.absences : DB.pointages).find(x => x.id === q.id && x.empId === emp.id);
    if (!rec) return fail(res, 404, 'Élément introuvable');
    if (kind === 'pointage' && !(rec.ecartMn > 0)) return fail(res, 400, 'Rien à justifier pour ce pointage.');
    if ((kind === 'absence' ? rec.dateFin : rec.date) < limite) return fail(res, 400, 'Délai de justification dépassé (60 jours).');
    if (rec.justif.statut === 'acceptee') return fail(res, 409, 'Déjà accepté par le service RH.');
    const motif = str(q.motif, 500);
    if (motif.length < 3) return fail(res, 400, 'Expliquez le motif (3 caractères minimum).');
    let piece = rec.justif.piece || null;
    if (q.piece) {
      const mm = typeof q.piece === 'string' && q.piece.match(/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/);
      if (!mm) return fail(res, 400, 'Pièce jointe invalide (photo JPEG attendue).');
      const buf = Buffer.from(mm[1], 'base64');
      if (buf.length > MAX_PIECE_BYTES || buf[0] !== 0xFF || buf[1] !== 0xD8) return fail(res, 400, 'Pièce jointe invalide ou trop lourde.');
      fs.mkdirSync(PIECES_DIR, { recursive: true });
      const name = `${kind}-${rec.id}-${Date.now()}.jpg`;
      fs.writeFileSync(path.join(PIECES_DIR, name), buf);
      if (piece) { try { fs.unlinkSync(path.join(PIECES_DIR, piece)); } catch (e) { /* ignoré */ } }
      piece = name;
    }
    rec.justif = newJustif('en_attente', { motif, piece, demandeTs: Date.now() });
    save();
    return sendJSON(res, 200, { ok: true });
  }
  return fail(res, 400, 'Action inconnue');
}

// ---------- RH ----------
function lireEmploye(b, existant) {
  const nom = str(b.nom, 120);
  if (!nom) return { error: 'Le nom est obligatoire' };
  const href = isTime(b.href) ? b.href : (existant ? existant.href : '08:00');
  const hdep = isTime(b.hdep) ? b.hdep : (existant ? existant.hdep : '17:30');
  if (toMin(hdep) <= toMin(href)) return { error: 'L\'heure de départ doit être après l\'heure d\'arrivée' };
  return {
    nom, poste: str(b.poste, 120), dept: str(b.dept, 120), href, hdep,
    statut: b.statut === 'Inactif' ? 'Inactif' : 'Actif',
    dateEntree: isDate(b.dateEntree) ? b.dateEntree : (existant ? existant.dateEntree : nowLocal().date)
  };
}

async function routesRH(req, res, p, M, session) {
  const today = nowLocal().date;
  let m;

  if (p === '/api/state' && M === 'GET') return sendJSON(res, 200, etatRH());

  // Employés
  if (p === '/api/employes' && M === 'POST') {
    const v = lireEmploye(await readBody(req));
    if (v.error) return fail(res, 400, v.error);
    const code = randomCode(10);
    const emp = Object.assign({ id: nid('E') }, v, { phonePaired: false, deviceSecret: null, pairCodeHash: sha256(code) });
    DB.employes.push(emp); save();
    return sendJSON(res, 200, { ok: true, id: emp.id, code });
  }
  if ((m = p.match(/^\/api\/employes\/(\w+)$/))) {
    const emp = findEmp(m[1]);
    if (!emp) return fail(res, 404, 'Employé introuvable');
    if (M === 'PUT') {
      const v = lireEmploye(await readBody(req), emp);
      if (v.error) return fail(res, 400, v.error);
      const renomme = v.nom !== emp.nom;
      Object.assign(emp, v);
      if (renomme) [DB.pointages, DB.absences, DB.conges].forEach(arr => arr.forEach(r => { if (r.empId === emp.id) r.empNom = emp.nom; }));
      save(); return sendJSON(res, 200, { ok: true });
    }
    if (M === 'DELETE') {
      DB.employes = DB.employes.filter(e => e.id !== emp.id);
      DB.conges = DB.conges.filter(c => c.empId !== emp.id || c.dateRetour <= today);
      save(); return sendJSON(res, 200, { ok: true });
    }
  }
  if ((m = p.match(/^\/api\/employes\/([\w]+)\/code$/)) && M === 'POST') {
    const emp = findEmp(m[1]);
    if (!emp) return fail(res, 404, 'Employé introuvable');
    const code = randomCode(10);
    emp.pairCodeHash = sha256(code); emp.deviceSecret = null; emp.phonePaired = false;
    save(); return sendJSON(res, 200, { ok: true, code });
  }

  // Pointage manuel
  if (p === '/api/pointages' && M === 'POST') {
    const b = await readBody(req);
    const emp = findEmp(str(b.empId, 32));
    const type = b.type === 'depart' ? 'depart' : 'arrivee';
    if (!emp) return fail(res, 400, 'Employé requis');
    if (!isDate(b.date) || b.date > today) return fail(res, 400, 'Date invalide (pas de date future)');
    if (!isTime(b.heure)) return fail(res, 400, 'Heure invalide');
    const hprev = isTime(b.hprev) ? b.hprev : (type === 'depart' ? emp.hdep : emp.href);
    if (DB.pointages.some(x => x.empId === emp.id && x.date === b.date && x.type === type)) return fail(res, 409, 'Un pointage de ce type existe déjà ce jour : supprimez-le d\'abord.');
    const { ecartMn, supMn } = calculEcarts(type, b.heure, hprev);
    const motif = str(b.motif, 500);
    const justif = ecartMn > 0 && b.accepte === true
      ? newJustif('acceptee', { motif, decisionTs: Date.now(), decisionPar: session.username })
      : newJustif('aucune', { motif });
    DB.pointages.push({ id: nid(), empId: emp.id, empNom: emp.nom, date: b.date, type, heure: b.heure, hprev, ecartMn, supMn, source: 'rh', justif, ts: Date.now() });
    retirerAbsencesAuto(emp.id, b.date, b.date);
    save(); return sendJSON(res, 200, { ok: true });
  }
  if ((m = p.match(/^\/api\/pointages\/(\w+)$/)) && M === 'DELETE') {
    const n = DB.pointages.length;
    DB.pointages = DB.pointages.filter(x => x.id !== m[1]);
    if (DB.pointages.length === n) return fail(res, 404, 'Introuvable');
    save(); return sendJSON(res, 200, { ok: true });
  }

  // Absences
  if (p === '/api/absences' && M === 'POST') {
    const b = await readBody(req);
    const emp = findEmp(str(b.empId, 32));
    if (!emp) return fail(res, 400, 'Employé requis');
    if (!isDate(b.dateDebut)) return fail(res, 400, 'Date de début invalide');
    const fin = isDate(b.dateFin) ? b.dateFin : b.dateDebut;
    if (fin < b.dateDebut) return fail(res, 400, 'La date de fin est avant la date de début');
    let jours = Number(b.jours);
    if (!(jours > 0)) jours = joursOuvres(b.dateDebut, fin) || 1;
    jours = Math.min(366, Math.round(jours * 2) / 2);
    const motif = str(b.motif, 300) || 'Non précisé';
    const justif = b.accepte === true
      ? newJustif('acceptee', { motif, decisionTs: Date.now(), decisionPar: session.username })
      : newJustif('aucune', { motif: '' });
    retirerAbsencesAuto(emp.id, b.dateDebut, fin);
    DB.absences.push({ id: nid(), empId: emp.id, empNom: emp.nom, dateDebut: b.dateDebut, dateFin: fin, jours, motif, source: 'rh', justif, ts: Date.now() });
    save(); return sendJSON(res, 200, { ok: true });
  }
  if ((m = p.match(/^\/api\/absences\/(\w+)$/)) && M === 'DELETE') {
    const n = DB.absences.length;
    DB.absences = DB.absences.filter(x => x.id !== m[1]);
    if (DB.absences.length === n) return fail(res, 404, 'Introuvable');
    save(); return sendJSON(res, 200, { ok: true });
  }

  // Congés
  if (p === '/api/conges' && M === 'POST') {
    const b = await readBody(req);
    const emp = findEmp(str(b.empId, 32));
    if (!emp) return fail(res, 400, 'Employé requis');
    if (!isDate(b.dateDebut) || !isDate(b.dateRetour)) return fail(res, 400, 'Dates invalides');
    if (b.dateRetour <= b.dateDebut) return fail(res, 400, 'La date de retour doit être après le premier jour de congé');
    if (DB.conges.some(c => c.empId === emp.id && c.dateDebut < b.dateRetour && b.dateDebut < c.dateRetour)) return fail(res, 409, 'Ce congé chevauche un congé déjà enregistré');
    const c = { id: nid('C'), empId: emp.id, empNom: emp.nom, type: str(b.type, 60) || 'Congé annuel', dateDebut: b.dateDebut, dateRetour: b.dateRetour, motif: str(b.motif, 300), jours: joursOuvres(b.dateDebut, addDays(b.dateRetour, -1)), parRH: session.username, ts: Date.now() };
    DB.conges.push(c);
    retirerAbsencesAuto(emp.id, b.dateDebut, addDays(b.dateRetour, -1));
    save(); return sendJSON(res, 200, { ok: true });
  }
  if ((m = p.match(/^\/api\/conges\/(\w+)\/terminer$/)) && M === 'POST') {
    const c = DB.conges.find(x => x.id === m[1]);
    if (!c) return fail(res, 404, 'Congé introuvable');
    if (c.dateDebut >= today) DB.conges = DB.conges.filter(x => x !== c);
    else { c.dateRetour = today; c.jours = joursOuvres(c.dateDebut, addDays(today, -1)); }
    save(); return sendJSON(res, 200, { ok: true });
  }
  if ((m = p.match(/^\/api\/conges\/(\w+)$/)) && M === 'DELETE') {
    const n = DB.conges.length;
    DB.conges = DB.conges.filter(x => x.id !== m[1]);
    if (DB.conges.length === n) return fail(res, 404, 'Introuvable');
    save(); return sendJSON(res, 200, { ok: true });
  }

  // Décision sur un justificatif
  if (p === '/api/justifications/decision' && M === 'POST') {
    const b = await readBody(req);
    const arr = b.kind === 'absence' ? DB.absences : DB.pointages;
    const rec = arr.find(x => x.id === b.id);
    if (!rec) return fail(res, 404, 'Élément introuvable');
    if (!JUSTIF_STATUTS.includes(b.decision)) return fail(res, 400, 'Décision invalide');
    rec.justif.statut = b.decision;
    rec.justif.commentaire = str(b.commentaire, 300);
    if (b.decision === 'acceptee' || b.decision === 'refusee') { rec.justif.decisionTs = Date.now(); rec.justif.decisionPar = session.username; }
    else { delete rec.justif.decisionTs; delete rec.justif.decisionPar; }
    save(); return sendJSON(res, 200, { ok: true });
  }
  if ((m = p.match(/^\/api\/justifications\/piece\/([\w-]+\.jpg)$/)) && M === 'GET') {
    const f = path.join(PIECES_DIR, m[1]);
    return fs.readFile(f, (err, data) => {
      if (err) return fail(res, 404, 'Pièce introuvable');
      res.writeHead(200, Object.assign({ 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, no-store' }, SEC_HEADERS));
      res.end(data);
    });
  }

  // Paramètres
  if (p === '/api/parametres' && M === 'POST') {
    const b = await readBody(req);
    const s = DB.settings;
    if (b.heureCloture !== undefined) { if (!isTime(b.heureCloture)) return fail(res, 400, 'Heure de clôture invalide'); s.heureCloture = b.heureCloture; }
    if (b.joursTravailles !== undefined) {
      if (!Array.isArray(b.joursTravailles)) return fail(res, 400, 'Jours travaillés invalides');
      s.joursTravailles = [...new Set(b.joursTravailles.map(Number).filter(n => Number.isInteger(n) && n >= 0 && n <= 6))].sort();
    }
    if (b.joursFeries !== undefined) {
      if (!Array.isArray(b.joursFeries)) return fail(res, 400, 'Jours fériés invalides');
      s.joursFeries = [...new Set(b.joursFeries.filter(isDate))].sort().slice(-300);
    }
    save(); tickCloture();
    return sendJSON(res, 200, { ok: true });
  }
  if (p === '/api/parametres/mot-de-passe' && M === 'POST') {
    const b = await readBody(req);
    const s = DB.settings;
    if (!safeEqual(hashPassword(typeof b.currentPassword === 'string' ? b.currentPassword : '', s.rhPasswordSalt), s.rhPasswordHash)) return fail(res, 401, 'Mot de passe actuel incorrect');
    const nu = str(b.newUsername, 60);
    if (b.newPassword) {
      if (typeof b.newPassword !== 'string' || b.newPassword.length < 8) return fail(res, 400, 'Le nouveau mot de passe doit faire au moins 8 caractères');
      s.rhPasswordSalt = makeSalt();
      s.rhPasswordHash = hashPassword(b.newPassword, s.rhPasswordSalt);
    }
    if (nu) s.rhUsername = nu;
    // Toutes les autres sessions sont déconnectées
    const mine = parseCookies(req).sid;
    for (const k of sessions.keys()) if (k !== mine) sessions.delete(k);
    const cur = sessions.get(mine); if (cur) cur.username = s.rhUsername;
    save(); return sendJSON(res, 200, { ok: true, username: s.rhUsername });
  }
  if (p === '/api/parametres/code-tablette' && M === 'POST') {
    DB.settings.kioskToken = randomCode(8);
    save(); return sendJSON(res, 200, { ok: true, kioskToken: DB.settings.kioskToken });
  }

  return fail(res, 404, 'Route inconnue');
}

// ============================================================
// DÉMARRAGE
// ============================================================
load();

const server = http.createServer((req, res) => {
  handle(req, res).catch(e => {
    if (res.headersSent) return;
    if (e.message === 'PAYLOAD_TOO_LARGE') return fail(res, 413, 'Envoi trop volumineux');
    if (e.message === 'INVALID_JSON') return fail(res, 400, 'Données invalides');
    console.error(e);
    fail(res, 500, 'Erreur serveur');
  });
});
server.requestTimeout = 30 * 1000;

if (require.main === module) {
  server.listen(PORT, () => {
    console.log('\n==========================================================');
    console.log('   Sha\'ah v2 démarré — port ' + PORT + ' — fuseau ' + TZ);
    console.log('   Données : ' + DATA_FILE);
    console.log('==========================================================\n');
    tickCloture();
    setInterval(tickCloture, 60 * 1000);
  });
}

module.exports = { server, _test: { tickCloture, cloturerJour, getDB: () => DB, nowLocal, addDays } };
