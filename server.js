const express = require('express');
const server = express();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const usersFile = path.join(__dirname, 'data', 'users.json');
const config = require(`${__dirname}/config.json`);

const port = config.port;
let users = require(usersFile);

// Middleware
server.use(express.json());
server.use(express.urlencoded({ extended: true }));
server.use(cookieParser());
server.use(session({
  secret: 'Reyette-secreet',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));
server.use(passport.initialize());
server.use(passport.session());

// Passport configuration
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, (email, password, done) => {
  const user = users.find((user) => user.email === email && user.password === password);
  if (user) {
    return done(null, user);
  } else {
    return done(null, false);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find((user) => user.id === id);
  done(null, user);
});

// Login form
server.get('/login', (req, res) => {
  res.sendFile(__dirname + '/views/login.html');
});

// Login route
server.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.redirect('/login?error=Email atau password salah');
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      req.session.username = user.username;
      res.redirect('/');
    });
  })(req, res, next);
});

// Logout route
server.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/login');
  });
});

// Registrasi form
server.get('/register', (req, res) => {
  res.sendFile(__dirname + '/views/register.html');
});

// Registrasi route
server.post('/register', (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  if (!username || !email || !password || !confirmPassword) {
    return res.redirect('/register?error=Username, email, dan kedua password harus diisi');
  }

  if (password !== confirmPassword) {
    return res.redirect('/register?error=Kedua password tidak cocok');
  }

  // Validasi email sederhana
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.redirect('/register?error=Email tidak valid');
  }
  
  // Periksa apakah email sudah digunakan
  const emailExists = users.some((user) => user.email === email);
  if (emailExists) {
    return res.redirect('/register?error=Email sudah digunakan');
  }

  // Periksa apakah username sudah digunakan
  const usernameExists = users.some((user) => user.username === username);
  if (usernameExists) {
    return res.redirect('/register?error=Username sudah digunakan');
  }

  const newUser = {
    id: users.length + 1,
    username,
    email,
    password
  };
  users.push(newUser);

  fs.writeFile(usersFile, JSON.stringify(users, null, 2), (err) => {
    if (err) {
      console.error(err);
      return res.redirect('/register?error=Terjadi kesalahan saat menyimpan data');
    }
    req.login(newUser, (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/register?error=Terjadi kesalahan saat login');
      }
      req.session.username = newUser.username;
      return res.redirect('/');
    });
  });
});

// Protected route
server.use((req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect('/login');
  }
});

// Main route
server.get('/', (req, res) => {
  var usrName = req.session.username;
  res.send(`Halo ${usrName} Selamat datang di server!`);
});

// Error handling
server.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Terjadi kesalahan!');
});

// Jalankan server
server.listen(port, () => {
  console.log(`Server berjalan pada port ${port}`);
});
