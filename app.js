// app.js
const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const app = express();

app.use(express.json()); // Pour parser les requêtes JSON

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

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});

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
