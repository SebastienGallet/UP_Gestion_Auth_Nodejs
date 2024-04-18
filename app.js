const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const app = express();
const jwt = require('jsonwebtoken');
require('dotenv').config();

app.use(express.json());

passport.use(new LocalStrategy(
  function(username, password, done) {
      const user = findUserByUsername(username);
      if (!user) {
          return done(null, false, { message: 'Incorrect username.' });
      }
      if (!validatePassword(user, password)) {
          return done(null, false, { message: 'Incorrect password.' });
      }
      return done(null, user);
  }
));



// Simuler une base de données d'utilisateurs en mémoire
const users = [
  { id: 1, username: "admin", password: "admin", role: "admin" },  // mot de passe doit être sécurisé dans une vraie appli
  { id: 2, username: "user", password: "user", role: "user" }
];

function findUserByUsername(username) {
  return users.find(user => user.username === username);
}

function validatePassword(user, password) {
  return user.password === password;
}

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
      if (err) return next(err);
      if (!user) return res.status(400).json({ message: info.message });
      
      // Utilisateur authentifié, générer un token avec le rôle inclus
      const token = jwt.sign({ username: user.username, role: user.role }, process.env.ACCESS_TOKEN_SECRET);
      res.json({ accessToken: token });
  })(req, res, next);
});



app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});




function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.sendStatus(403);
    req.user = decoded; // decoded token inclut désormais le rôle de l'utilisateur
    next();
  });
}

app.get('/protected', authenticateToken, roleAuthorization(['admin']), (req, res) => {
  res.json({ message: "Vous êtes authentifié et avez accès à cette zone protégée en tant qu'admin." });
});

const roles = ["admin", "editor", "user"];

function roleAuthorization(rolesAllowed) {
  return function(req, res, next) {
    const userRole = req.user.role;
    if (rolesAllowed.includes(userRole)) {
      next();
    } else {
      res.status(403).json({message: "Accès refusé : Vous n'avez pas les droits nécessaires pour cette action."});
    }
  }
}

// Exemple de middleware HTTPS forcé
app.use((req, res, next) => {
  if (req.secure) {
    next();
  } else {
    res.redirect('https://' + req.headers.host + req.url);
  }
});

// Exemple de gestion sécurisée des secrets avec dotenv
console.log(process.env.SECRET);  // Accéder à un secret sécurisé
