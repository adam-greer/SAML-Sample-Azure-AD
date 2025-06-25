// app.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const SamlStrategy = require('passport-saml').Strategy;
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'jade');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.MY_SESSION_SECRET || 'defaultsecret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

const usersFile = path.join(__dirname, 'users.json');
function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(usersFile));
  } catch {
    return [];
  }
}
function saveUsers(data) {
  fs.writeFileSync(usersFile, JSON.stringify(data, null, 2));
}

const users = [
  { id: 1, username: 'admin', passwordHash: bcrypt.hashSync('password', 10), isAdmin: true }
];

function addOrUpdateUser(user) {
  const users = loadUsers();
  const idx = users.findIndex(u => u.email === user.email);

  if (idx >= 0) {
    if (typeof user.isAdmin === 'undefined') {
      user.isAdmin = users[idx].isAdmin || false;
    }
    users[idx] = { ...users[idx], ...user };
  } else {
    user.isAdmin = user.isAdmin || false;
    users.push(user);
  }

  saveUsers(users);
}

passport.use(new LocalStrategy((username, password, done) => {
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) return done(null, false);
  return done(null, user);
}));

let samlStrategyInstance;
function initSamlStrategy() {
  if (samlStrategyInstance) {
    try { passport.unuse('saml'); } catch {}
    samlStrategyInstance = null;
  }

  // Convert literal \n in env var to actual newlines for the PEM cert
  const cert = process.env.AZURE_AD_SAML_CERT_B64?.replace(/\\n/g, '\n');
  if (!cert || !process.env.SAML_CALLBACK_URL || !process.env.AZURE_AD_TENANT_ID || !process.env.AZURE_AD_ENTERPRISE_APP_SAML_Identifier) {
    console.warn('SAML config incomplete, skipping SAML strategy initialization');
    return;
  }

  samlStrategyInstance = new SamlStrategy({
    callbackUrl: process.env.SAML_CALLBACK_URL,
    entryPoint: `https://login.microsoftonline.com/${process.env.AZURE_AD_TENANT_ID}/saml2`,
    issuer: process.env.AZURE_AD_ENTERPRISE_APP_SAML_Identifier,
    cert,
    signatureAlgorithm: 'sha256'
  }, (profile, done) => {
    done(null, {
      id: profile.nameID,
      email: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
      displayName: profile['http://schemas.microsoft.com/identity/claims/displayname'],
      firstName: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'],
      lastName: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'],
      title: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/title'],
    });
  });

  passport.use('saml', samlStrategyInstance);
}
initSamlStrategy();

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => {
  // Check if local user
  if (user.username) {
    const localUser = users.find(u => u.username === user.username);
    if (localUser) {
      user.isAdmin = localUser.isAdmin || false;
    }
  } else if (user.email) {  // SAML user
    const allUsers = loadUsers();
    const matched = allUsers.find(u => u.email === user.email);
    user.isAdmin = matched ? matched.isAdmin : false;
  }
  return done(null, user);
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}
function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.isAdmin) return next();
  res.status(403).send('Admins only');
}

app.get('/login', (req, res) => res.render('login', { samlEnabled: !!samlStrategyInstance }));
app.get('/login/local', (req, res) => res.render('login_local'));
app.post('/login/local', passport.authenticate('local', { successRedirect: '/profile', failureRedirect: '/login/local' }));

app.get('/login/saml', passport.authenticate('saml', { failureRedirect: '/login' }));
app.post('/login/callback', passport.authenticate('saml', { failureRedirect: '/login' }), (req, res) => {
  const p = req.user;

  const userObj = {
    email: p.email,
    firstName: p.firstName,
    lastName: p.lastName,
    title: p.title,
    displayName: p.displayName,
    authType: 'saml'
  };

  addOrUpdateUser(userObj);

  const allUsers = loadUsers();
  const fullUser = allUsers.find(u => u.email === userObj.email);

  req.session.userProfile = fullUser || userObj;
  res.redirect('/profile');
});

app.get('/profile', ensureAuthenticated, (req, res) => {
  const profile = req.session.userProfile || req.user;
  res.render('profile', { user: profile });
});

app.get('/users', ensureAdmin, (req, res) => {
  const allUsers = [...loadUsers(), ...users.map(u => ({
    email: u.username,
    displayName: u.username,
    authType: 'local',
    isAdmin: u.isAdmin
  }))];
  res.render('users', { users: allUsers });
});

app.post('/users/:email/admin-toggle', ensureAdmin, (req, res) => {
  const target = req.params.email;
  const makeAdmin = req.body.isAdmin === 'on';

  let updated = false;
  const fileUsers = loadUsers();
  const jsonIdx = fileUsers.findIndex(u => u.email === target);
  if (jsonIdx !== -1) {
    fileUsers[jsonIdx].isAdmin = makeAdmin;
    saveUsers(fileUsers);
    updated = true;
  } else {
    const localIdx = users.findIndex(u => u.username === target);
    if (localIdx !== -1) {
      users[localIdx].isAdmin = makeAdmin;
      updated = true;
    }
  }

  if (updated && (req.user.email === target || req.user.username === target)) {
    req.login(req.user, err => {
      if (err) console.error(err);
      res.redirect('/users');
    });
  } else {
    res.redirect('/users');
  }
});

app.get('/admin/env', ensureAdmin, (req, res) => {
  const envPath = path.join(__dirname, '.env');
  const parsed = dotenv.parse(fs.readFileSync(envPath));
  res.render('admin_env', {
    envVars: {
      SAML_CALLBACK_URL: parsed.SAML_CALLBACK_URL || '',
      AZURE_AD_TENANT_ID: parsed.AZURE_AD_TENANT_ID || '',
      AZURE_AD_ENTERPRISE_APP_SAML_Identifier: parsed.AZURE_AD_ENTERPRISE_APP_SAML_Identifier || '',
      AZURE_AD_SAML_CERT_B64: parsed.AZURE_AD_SAML_CERT_B64 || ''
    }
  });
});

app.post('/admin/env/save', ensureAdmin, (req, res) => {
  const entries = Object.entries(req.body).map(([k, v]) => `${k}=${v}`).join('\n');
  const envPath = path.join(__dirname, '.env');
  fs.writeFileSync(envPath, entries);
  dotenv.config({ path: envPath, override: true });
  initSamlStrategy();
  res.redirect('/profile');
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/login'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

