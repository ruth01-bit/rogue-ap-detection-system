async function loadAccessPoints() {

    const response = await fetch("/get_access_points")

    const data = await response.json()

    const table = document.getElementById("table-body")

    table.innerHTML = ""

    let safeCount = 0

    let rogueCount = 0

    data.forEach(ap => {

        const row = document.createElement("tr")

        if (ap.status === "SAFE") {

            row.classList.add("safe")

            safeCount++

        }

        else if (ap.status === "WARNING") {

            row.classList.add("warning")

        }

        else {

            row.classList.add("danger")

            rogueCount++

        }

        row.innerHTML = `
            <td>${ap.ssid}</td>
            <td>${ap.bssid}</td>
            <td>${ap.signal}</td>
            <td>${ap.encryption}</td>
            <td>${ap.status}</td>
            <td>${ap.threat}</td>
        `

        table.appendChild(row)
    })

    document.getElementById("safe-count").innerText = safeCount

    document.getElementById("rogue-count").innerText = rogueCount

    const status = document.getElementById("security-status")

    if (rogueCount >= 3) {

        status.innerText = "UNDER ATTACK"

        status.style.color = "#ef4444"
    }

    else {

        status.innerText = "SECURE"

        status.style.color = "#22c55e"
    }
}

async function scanNetworks() {

    await fetch("/scan")

    loadAccessPoints()
}

loadAccessPoints()

setInterval(loadAccessPoints, 5000)
