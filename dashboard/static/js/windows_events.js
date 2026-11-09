
"use strict";

let currentWindowsEvents = [];

function createCell(value) {
    const td = document.createElement("td");
    td.textContent = value ?? "-";
    return td;
}

function displayWindowsEvents(events) {
    const body = document.getElementById("windowsEventsBody");
    body.replaceChildren();

    if (events.length === 0) {
        const row = document.createElement("tr");
        const cell = createCell("No matching Windows events found.");
        cell.colSpan = 8;
        row.appendChild(cell);
        body.appendChild(row);
        return;
    }

    for (const event of events) {
        const row = document.createElement("tr");

        row.appendChild(createCell(event.timestamp));
        row.appendChild(createCell(event.windows_event_id));
        row.appendChild(createCell(
            event.event_type === "SUCCESS_LOGIN"
                ? "SUCCESS"
                : "FAILED"
        ));
        row.appendChild(createCell(event.logon_type_name));
        row.appendChild(createCell(event.username));
        row.appendChild(createCell(event.source_ip));
        row.appendChild(createCell(event.computer));

        const actionCell = document.createElement("td");
        const button = document.createElement("button");

        button.className = "btn";
        button.textContent = "Inspect";
        button.addEventListener("click", () => {
            showWindowsEventDetails(event);
        });

        actionCell.appendChild(button);
        row.appendChild(actionCell);
        body.appendChild(row);
    }
}

function showWindowsEventDetails(event) {
    const panel = document.getElementById("windowsDetailsPanel");
    const details = document.getElementById("windowsEventDetails");

    details.textContent = JSON.stringify(event, null, 2);
    panel.hidden = false;
    panel.scrollIntoView({ behavior: "smooth" });
}

async function loadWindowsEvents() {
    const search = document.getElementById("windowsSearch").value;
    const type = document.getElementById("windowsEventType").value;
    const logonType = document.getElementById("windowsLogonType").value;

    const params = new URLSearchParams({
        search,
        type,
        logon_type: logonType
    });

    const message = document.getElementById("windowsEventsMessage");
    message.textContent = "Loading Windows events...";

    try {
        const response = await fetch(
            `/api/windows-events?${params.toString()}`,
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error(
                `Request failed: ${response.status}`
            );
        }

        const data = await response.json();

        currentWindowsEvents = data.events;
        displayWindowsEvents(currentWindowsEvents);

        message.textContent =
            `Displaying ${data.total} Windows events.`;

    } catch (error) {
        message.textContent = error.message;
        console.error(error);
    }
}

document.getElementById(
    "refreshWindowsEvents"
).addEventListener("click", loadWindowsEvents);

document.getElementById(
    "applyWindowsFilters"
).addEventListener("click", loadWindowsEvents);

document.getElementById(
    "clearWindowsFilters"
).addEventListener("click", () => {
    document.getElementById("windowsSearch").value = "";
    document.getElementById("windowsEventType").value = "ALL";
    document.getElementById("windowsLogonType").value = "ALL";
    loadWindowsEvents();
});

loadWindowsEvents();
