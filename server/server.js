const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');

const app = express();
const port = 3000;

// Parsowanie formularzy i JSON
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Konfiguracja sesji
app.use(session({
    secret: 'moja_tajemnica_sesji',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Połączenie z bazą danych SQLite
const db = new sqlite3.Database('users.db');

// Tworzenie tabeli użytkowników
db.serialize(() => {
    db.run(`
         CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            level INTEGER DEFAULT 1,
            gold INTEGER DEFAULT 100,
            strength INTEGER DEFAULT 10,
            defense INTEGER DEFAULT 10,
            health INTEGER DEFAULT 100,
            speed INTEGER DEFAULT 5,
            prestige_points INTEGER DEFAULT 0,
            last_upgrade_cost_strength INTEGER DEFAULT 10,
            last_upgrade_cost_defense INTEGER DEFAULT 10,
            last_upgrade_cost_health INTEGER DEFAULT 10,
            last_upgrade_cost_speed INTEGER DEFAULT 10
        )
    `);
});

// Obsługa plików statycznych
app.use(express.static(path.join(__dirname, 'public')));

// Globalny handler błędów Express
app.use((err, req, res, next) => {
    console.error('Wystąpił błąd:', err.stack);
    res.status(500).send('Coś poszło nie tak!');
});


// Endpoint wyświetlający stronę logowania
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Endpoint wyświetlający stronę rejestracji
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Endpoint rejestracji
app.post('/register', (req, res) => {
    const { username, email, password, class: chosenClass } = req.body;
    let initialStats;

    // Określanie statystyk na podstawie wybranej klasy postaci
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
            return res.status(400).json({ success: false, message: 'Nieznana klasa postaci' });
    }

    // Sprawdzanie, czy użytkownik już istnieje
    db.get('SELECT username, email FROM users WHERE username = ? OR email = ?', [username, email], (err, row) => {
        if (row) {
            return res.json({ success: false, message: 'Nazwa użytkownika lub email są już zajęte' });
        }

        // Haszowanie hasła i zapisywanie użytkownika w bazie
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) return res.json({ success: false, message: 'Błąd haszowania hasła' });

            db.run(`INSERT INTO users (username, email, password, strength, defense, health, speed) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [username, email, hashedPassword, initialStats.strength, initialStats.defense, initialStats.health, initialStats.speed],
                (err) => {
                    if (err) return res.json({ success: false, message: 'Błąd podczas rejestracji' });
                    res.json({ success: true });
                }
            );
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (!user) {
            return res.json({ success: false, message: 'Nie znaleziono użytkownika' });
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, updatedUser) => {
                    if (err) {
                        return res.status(500).json({ success: false, message: 'Błąd serwera podczas logowania' });
                    }

                    // Przypisz dane użytkownika do sesji
                    req.session.user = updatedUser;

                    // Logowanie danych sesji dla debugowania
                    console.log('Dane sesji użytkownika po zalogowaniu:', req.session.user);

                    res.json({
                        success: true,
                        user: updatedUser
                    });
                });
            } else {
                return res.json({ success: false, message: 'Nieprawidłowe hasło' });
            }
        });
    });
});


// Endpoint dodający punkty prestiżu po wygranej walce
app.post('/win-fight', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: 'Musisz być zalogowany, aby zdobywać punkty prestiżu.' });
    }

    const userId = req.session.user.id;
    const prestigePointsToAdd = 10;  // Na razie ustalamy, że gracz zdobywa 10 punktów za wygraną

    db.run(`UPDATE users SET prestige_points = prestige_points + ? WHERE id = ?`, [prestigePointsToAdd, userId], function(err) {
        if (err) {
            console.error('Błąd SQL:', err);  // Logowanie błędu SQL
            return res.status(500).json({ message: 'Błąd podczas aktualizowania punktów prestiżu.' });
        }

        res.json({ success: true, message: `Gratulacje! Zdobyłeś ${prestigePointsToAdd} punktów prestiżu.` });
    });
});
// Funkcja obliczania nowego kosztu ulepszenia
const calculateNewUpgradeCost = (lastCost) => {
    return Math.floor(lastCost * 1.1); // Koszt rośnie o 10% z zaokrągleniem w dół
};

// Endpoint do ulepszania statystyk z dynamicznym kosztem (x + 10%)
app.post('/upgrade-stat', (req, res) => {
    const { stat } = req.body; // Pobieramy statystykę, którą chcemy ulepszyć (strength, defense, health, speed)
    const userId = req.session.user.id; // Pobieramy ID użytkownika z sesji

    // Znajdź użytkownika w bazie danych
    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) {
            return res.status(400).json({ success: false, message: 'Użytkownik nie istnieje' });
        }

        // Ustalanie, którą statystykę zwiększyć i który koszt sprawdzić
        let currentStatValue, lastUpgradeCostField, currentCost;
        switch (stat) {
            case 'strength':
                currentStatValue = user.strength;
                lastUpgradeCostField = 'last_upgrade_cost_strength';
                currentCost = user.last_upgrade_cost_strength;
                break;
            case 'defense':
                currentStatValue = user.defense;
                lastUpgradeCostField = 'last_upgrade_cost_defense';
                currentCost = user.last_upgrade_cost_defense;
                break;
            case 'health':
                currentStatValue = user.health;
                lastUpgradeCostField = 'last_upgrade_cost_health';
                currentCost = user.last_upgrade_cost_health;
                break;
            case 'speed':
                currentStatValue = user.speed;
                lastUpgradeCostField = 'last_upgrade_cost_speed';
                currentCost = user.last_upgrade_cost_speed;
                break;
            default:
                return res.status(400).json({ success: false, message: 'Nieprawidłowa statystyka' });
        }

        const newCost = calculateNewUpgradeCost(currentCost);

        if (user.gold < newCost) {
            return res.status(400).json({ success: false, message: 'Nie masz wystarczającej ilości złota' });
        }

        const newGold = user.gold - newCost;
        const updatedStatValue = currentStatValue + 1;

        // Aktualizacja bazy danych
        db.run(`UPDATE users SET ${stat} = ?, gold = ?, ${lastUpgradeCostField} = ? WHERE id = ?`,
            [updatedStatValue, newGold, newCost, userId], function(err) {
                if (err) {
                    console.error('Błąd podczas aktualizacji statystyki:', err.message);
                    return res.status(500).json({ success: false, message: 'Błąd podczas aktualizacji statystyki' });
                }

                // POBIERAMY ZAKTUALIZOWANE DANE I AKTUALIZUJEMY SESJĘ
                db.get('SELECT * FROM users WHERE id = ?', [userId], (err, updatedUser) => {
                    if (err) {
                        console.error('Błąd podczas odświeżania danych użytkownika:', err.message);
                        return res.status(500).json({ message: 'Błąd podczas odświeżania danych użytkownika' });
                    }

                    // Aktualizujemy sesję użytkownika
                    req.session.user = updatedUser;

                    // Dodajemy logowanie dla debugowania (możesz to usunąć po testach)
                    console.log('Zaktualizowane dane sesji dla użytkownika:', updatedUser.username, ' | Siła:', updatedUser.strength, ' | Złoto:', updatedUser.gold);

                    // Zwracamy odpowiedź do klienta
                    res.json({
                        success: true,
                        message: `Ulepszono ${stat}. Nowa wartość: ${updatedStatValue}`,
                        newGold: newGold,
                        updatedStat: updatedStatValue,
                        nextUpgradeCost: newCost
                    });
                });
            }
        );
    });
});

// Endpoint zwracający ranking graczy
app.get('/ranking', (req, res) => {
    db.all('SELECT username, prestige_points FROM users ORDER BY prestige_points DESC LIMIT 10', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Błąd podczas pobierania rankingu.' });
        }

        res.json(rows);
    });
});
// Funkcja do ulepszania statystyk
function upgradeStat(stat) {
    const userId = 1; // Pobierz rzeczywiste id użytkownika z sesji

    fetch('/upgrade-stat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stat, userId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Wyświetlanie komunikatu na stronie zamiast alert()
            const messageDiv = document.getElementById('message');
            messageDiv.style.display = 'block';
            messageDiv.innerText = `${stat} ulepszono! Nowa wartość: ${data.updatedStat}`;
            
            // Zaktualizuj wyświetlane statystyki
            document.getElementById(`character-${stat}`).innerText = data.updatedStat;
            document.getElementById('character-gold').innerText = data.newGold;

            // Ukryj komunikat po 3 sekundach
            setTimeout(() => {
                messageDiv.style.display = 'none';
            }, 3000);
        } else {
            alert(data.message);
        }
    })
    .catch(error => {
        console.error('Błąd podczas ulepszania:', error);
    });
}


// Endpoint zwracający listę graczy, z którymi można walczyć
app.get('/players', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: 'Musisz być zalogowany, aby zobaczyć listę graczy.' });
    }

    const userId = req.session.user.id;

    db.all('SELECT id, username FROM users WHERE id != ?', [userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Błąd podczas pobierania listy graczy.' });
        }

        res.json(rows);
    });
});
// Endpoint obsługujący walkę między graczami
app.post('/fight', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: 'Musisz być zalogowany, aby walczyć.' });
    }

    const userId = req.session.user.id;
    const opponentId = req.body.opponentId;

    // Pobierz statystyki gracza i przeciwnika
    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, player) => {
        if (err || !player) return res.status(500).json({ message: 'Błąd podczas pobierania statystyk gracza.' });

        db.get('SELECT * FROM users WHERE id = ?', [opponentId], (err, opponent) => {
            if (err || !opponent) return res.status(500).json({ message: 'Błąd podczas pobierania statystyk przeciwnika.' });

            // Mechanizm walki: porównanie statystyk
            const playerPower = player.strength + player.defense;
            const opponentPower = opponent.strength + opponent.defense;

            if (playerPower > opponentPower) {
                // Gracz wygrywa
                db.run('UPDATE users SET prestige_points = prestige_points + 10 WHERE id = ?', [userId]);
                return res.json({ success: true, message: 'Wygrałeś walkę i zdobyłeś 10 punktów prestiżu!' });
            } else if (playerPower < opponentPower) {
                // Przeciwnik wygrywa
                db.run('UPDATE users SET prestige_points = prestige_points + 10 WHERE id = ?', [opponentId]);
                return res.json({ success: true, message: `Przegrałeś walkę. ${opponent.username} zdobył 10 punktów prestiżu.` });
            } else {
                // Remis
                return res.json({ success: true, message: 'Remis w walce!' });
            }
        });
    });
});

// Endpoint wyświetlający stronę profilu (zabezpieczony, tylko dla zalogowanych użytkowników)
app.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// Endpoint zwracający dane profilu użytkownika w formacie JSON (tylko dla zalogowanych użytkowników)
app.get('/profile-data', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: 'Użytkownik nie jest zalogowany' });
    }

    const userId = req.session.user.id;

    // Pobierz dane użytkownika z bazy danych na podstawie jego sesji
    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) return res.status(500).json({ message: 'Błąd serwera' });
        if (!user) return res.status(404).json({ message: 'Nie znaleziono użytkownika' });

        res.json({
            username: user.username,
            level: user.level,
            gold: user.gold,
            strength: user.strength,
            defense: user.defense,
            health: user.health,
            speed: user.speed,
            cost_strength: user.last_upgrade_cost_strength,
            cost_defense: user.last_upgrade_cost_defense,
            cost_health: user.last_upgrade_cost_health,
            cost_speed: user.last_upgrade_cost_speed
        });
    });
});

// Endpoint wyświetlający stronę gry (zabezpieczony, tylko dla zalogowanych użytkowników)
app.get('/game', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'game.html'));
});

// Endpoint wylogowania użytkownika
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Błąd wylogowania');
        }
        res.redirect('/login');
    });
});

const server = app.listen(port, () => {
    console.log(`Serwer działa na porcie ${port}`);
});

// Obsługa poprawnego zamknięcia serwera
process.on('SIGINT', () => {
    server.close(() => {
        console.log('Serwer został zamknięty');
        process.exit(0);
    });
});
