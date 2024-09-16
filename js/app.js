// Symulowane dane użytkownika (możesz je zamienić na dane z serwera)
const userData = {
    username: "aaa",
    level: 1,
    gold: 100,
    strength: 15,
    defense: 18,
    health: 120,
    speed: 5
};

// Funkcja wyświetlająca dane użytkownika
function displayUserData(data) {
    const userInfoDiv = document.getElementById('user-info');

    const userHTML = `
        <h3>Witaj, ${data.username}!</h3>
        <ul>
            <li>Poziom: ${data.level}</li>
            <li>Złoto: ${data.gold}</li>
            <li>Siła: ${data.strength}</li>
            <li>Obrona: ${data.defense}</li>
            <li>Zdrowie: ${data.health}</li>
            <li>Szybkość: ${data.speed}</li>
        </ul>
    `;

    // Wstawiamy wygenerowany HTML do div
    userInfoDiv.innerHTML = userHTML;
}

// Wywołanie funkcji, aby wyświetlić dane
displayUserData(userData);
