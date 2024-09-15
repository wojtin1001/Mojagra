const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');

const app = express(); // Tutaj tworzysz aplikację Express
// Parsowanie application/x-www-form-urlencoded (formularz HTML)
app.use(bodyParser.urlencoded({ extended: true }));

// Parsowanie application/json (dla zapytań JSON)
app.use(bodyParser.json());
const port = 3000;

// Tworzymy połączenie z bazą danych SQLite
const db = new sqlite3.Database('users.db');

// Tworzymy tabelę użytkowników, jeśli jeszcze nie istnieje
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            level INTEGER DEFAULT 1,
            gold INTEGER DEFAULT 100,
            strength INTEGER DEFAULT 10
        )
    `);
});

// Middleware do parsowania JSON z zapytań
app.use(bodyParser.json());

// Konfiguracja sesji
app.use(session({
    secret: 'moja_tajemnica_sesji', // Sekret do podpisywania sesji
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // 'secure: true' wymaga HTTPS
}));

// Ustawienie serwera do obsługi plików statycznych (np. HTML, CSS, JS) z folderu public
app.use(express.static(path.join(__dirname, 'public')));

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Endpoint rejestracji użytkownika
app.post('/register', (req, res) => {
    console.log(req.body); // Logowanie danych przesłanych z formularza

    const { username, email, password, class: chosenClass } = req.body;

    // Logowanie wybranej klasy postaci
    console.log("Wybrana klasa postaci: ", chosenClass);

    // Ustalanie początkowych statystyk na podstawie wybranej klasy
    let initialStats;
    switch (chosenClass) {
        case 'Battle Smith':
            initialStats = { strength: 15, defense: 18, health: 120, speed: 5 };
            break;
        case 'Engineer':
            initialStats = { strength: 12, defense: 10, health: 110, speed: 8 };
            break;
        case 'Berserker':
            initialStats = { strength: 20, defense: 8, health: 130, speed: 7 };
            break;
        case 'Miner Warrior':
            initialStats = { strength: 18, defense: 15, health: 130, speed: 6 };
            break;
        case 'Earth Priest':
            initialStats = { strength: 10, defense: 12, health: 100, speed: 6 };
            break;
        default:
            console.log("Nieznana klasa: ", chosenClass);
            return res.status(400).json({ success: false, message: 'Nieznana klasa postaci' });
    }

    // Sprawdzenie, czy użytkownik o tej nazwie lub email już istnieje
    db.get('SELECT username, email FROM users WHERE username = ? OR email = ?', [username, email], (err, row) => {
        if (row) {
            return res.json({ success: false, message: 'Nazwa użytkownika lub email są już zajęte' });
        }

        // Haszowanie hasła
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.json({ success: false, message: 'Błąd haszowania hasła' });
            }

            // Próbujemy wstawić nowego użytkownika do bazy z odpowiednimi statystykami
            db.run(
                `INSERT INTO users (username, email, password, class, strength, defense, health, speed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [username, email, hashedPassword, chosenClass, initialStats.strength, initialStats.defense, initialStats.health, initialStats.speed],
                function (err) {
                    if (err) {
                        console.log("Błąd podczas wstawiania użytkownika do bazy danych:", err.message);
                        return res.json({ success: false, message: 'Błąd podczas rejestracji' });
                    }
                    res.json({ success: true });
                }
            );
        });
    });
});


// Endpoint logowania użytkownika
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (!user) {
            return res.json({ success: false, message: 'Nie znaleziono użytkownika' });
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.user = user;
                return res.json({ success: true });
            } else {
                return res.json({ success: false, message: 'Nieprawidłowe hasło' });
            }
        });
    });
});

// Endpoint sprawdzający, czy użytkownik jest zalogowany
app.get('/session', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user.username });
    } else {
        res.json({ loggedIn: false });
    }
});

// Endpoint wylogowania użytkownika
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.json({ success: false, message: 'Błąd podczas wylogowywania' });
        }
        res.json({ success: true });
    });
});

// Endpoint pobierający dane o zalogowanym użytkowniku (profil gracza)
app.get('/profile', (req, res) => {
    if (!req.session.user) {
        console.log("Błąd: użytkownik nie jest zalogowany.");
        return res.status(401).json({ message: 'Użytkownik nie jest zalogowany' });
    }

    const userId = req.session.user.id;

    // Logujemy dane użytkownika z sesji
    console.log("ID użytkownika z sesji:", userId);

    // Sprawdzamy, czy userId jest poprawne
    if (!userId) {
        console.log("Błąd: brak userId w sesji.");
        return res.status(500).json({ message: 'Błąd w sesji: brak userId' });
    }

    // Pobieramy dane użytkownika z bazy danych
    db.get('SELECT username, level, gold, strength FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.log("Błąd podczas pobierania danych użytkownika:", err.message);
            return res.status(500).json({ message: 'Błąd serwera podczas pobierania danych użytkownika' });
        }

        if (!user) {
            console.log("Nie znaleziono użytkownika o ID:", userId);
            return res.status(404).json({ message: 'Nie znaleziono użytkownika' });
        }

        // Logujemy dane użytkownika
        console.log("Dane użytkownika:", user);

        // Zwracamy dane użytkownika
        res.json({
            username: user.username,
            level: user.level,
            gold: user.gold,
            strength: user.strength
        });
    });
});

// Endpoint do ulepszania siły gracza z logami
app.post('/upgrade-strength', (req, res) => {
    if (!req.session.user) {
        console.log("Brak użytkownika w sesji.");
        return res.status(401).json({ success: false, message: 'Użytkownik nie jest zalogowany' });
    }

    const userId = req.session.user.id;

    db.get('SELECT gold, strength FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.log("Błąd pobierania danych użytkownika:", err.message);
            return res.status(500).json({ success: false, message: 'Błąd pobierania danych użytkownika' });
        }

        if (user) {
            console.log("Dane użytkownika:", user);
            if (user.gold >= 50) {
                const newGold = user.gold - 50;
                const newStrength = user.strength + 1;

                db.run('UPDATE users SET gold = ?, strength = ? WHERE id = ?', [newGold, newStrength, userId], function(err) {
                    if (err) {
                        console.log("Błąd aktualizacji użytkownika:", err.message);
                        return res.status(500).json({ success: false, message: 'Błąd aktualizacji danych użytkownika' });
                    }
                    console.log("Siła ulepszona, złoto zaktualizowane.");
                    res.json({ success: true });
                });
            } else {
                console.log("Brak wystarczającej ilości złota:", user.gold);
                res.json({ success: false, message: 'Nie masz wystarczająco złota' });
            }
        } else {
            console.log("Użytkownik nie znaleziony.");
            res.status(404).json({ success: false, message: 'Nie znaleziono użytkownika' });
        }
    });
});

// Endpoint do tymczasowego zwiększania ilości złota gracza (do testów)
app.post('/add-gold', (req, res) => {
    if (!req.session.user) {
        console.log("Brak zalogowanego użytkownika w sesji.");
        return res.status(401).json({ success: false, message: 'Użytkownik nie jest zalogowany' });
    }

    const userId = req.session.user.id;

    console.log("Próba aktualizacji złota dla użytkownika o ID:", userId);

    if (!userId) {
        console.log("Błąd: brak userId w sesji.");
        return res.status(500).json({ success: false, message: 'Błąd sesji: brak userId' });
    }

    db.run('UPDATE users SET gold = gold + 100 WHERE id = ?', [userId], function(err) {
        if (err) {
            console.log("Błąd aktualizacji złota:", err.message);
            return res.status(500).json({ success: false, message: 'Błąd aktualizacji złota' });
        }
        console.log("Zaktualizowano złoto dla użytkownika:", userId);
        res.json({ success: true, message: 'Dodano 100 złota' });
    });
});

// Uruchomienie serwera
app.listen(port, () => {
    console.log(`Serwer działa na porcie http://localhost:${port}`);
});
