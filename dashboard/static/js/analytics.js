"use strict";

const chartInstances = {};

const chartColors = {
    critical: "#fb7185",
    high: "#fb923c",
    medium: "#facc15",
    low: "#34d399",
    blue: "#38bdf8",
    purple: "#a78bfa"
};

function chartOptions(horizontal = false) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: horizontal ? "y" : "x",
        plugins: {
            legend: {
                labels: {
                    color: "#b4c2d5"
                }
            }
        },
        scales: {
            x: {
                ticks: { color: "#8b9bb2" },
                grid: { color: "#253248" }
            },
            y: {
                beginAtZero: true,
                ticks: {
                    color: "#8b9bb2",
                    precision: 0
                },
                grid: { color: "#253248" }
            }
        }
    };
}

function replaceChart(id, configuration) {
    if (chartInstances[id]) {
        chartInstances[id].destroy();
    }

    const element = document.getElementById(id);

    if (!element) {
        return;
    }

    chartInstances[id] = new Chart(
        element,
        configuration
    );
}

function renderSeverityChart(data) {
    const labels = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ];

    replaceChart("severityChart", {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                data: labels.map(
                    label => data.severity[label] || 0
                ),
                backgroundColor: [
                    chartColors.critical,
                    chartColors.high,
                    chartColors.medium,
                    chartColors.low
                ],
                borderColor: "#111b2b",
                borderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#b4c2d5",
                        padding: 20
                    }
                }
            }
        }
    });
}

function renderAttackChart(data) {
    const labels = data.attack_types.map(
        item => item.alert_type.replaceAll("_", " ")
    );

    const values = data.attack_types.map(
        item => item.total
    );

    replaceChart("attackChart", {
        type: "bar",
        data: {
            labels,
            datasets: [{
                label: "Detected Alerts",
                data: values,
                backgroundColor: chartColors.blue,
                borderRadius: 6
            }]
        },
        options: chartOptions(true)
    });
}

function renderActivityChart(data) {
    const labels = data.event_activity.map(
        item => item.day
    );

    const values = data.event_activity.map(
        item => item.total
    );

    replaceChart("activityChart", {
        type: "line",
        data: {
            labels,
            datasets: [{
                label: "Security Events",
                data: values,
                borderColor: chartColors.blue,
                backgroundColor: "rgba(56,189,248,0.12)",
                fill: true,
                tension: 0.35,
                pointRadius: 4
            }]
        },
        options: chartOptions()
    });
}

function renderInvestigationSummary(data) {
    const container = document.getElementById(
        "investigationSummary"
    );

    const statuses = [
        ["OPEN", "Open"],
        ["INVESTIGATING", "Investigating"],
        ["RESOLVED", "Resolved"],
        ["FALSE_POSITIVE", "False Positive"]
    ];

    container.replaceChildren();

    for (const [key, label] of statuses) {
        const card = document.createElement("div");
        card.className = "investigation-card";

        const name = document.createElement("span");
        name.textContent = label;

        const value = document.createElement("strong");
        value.textContent =
            data.investigation_status[key] || 0;

        card.append(name, value);
        container.appendChild(card);
    }
}

async function loadAnalytics() {
    const message = document.getElementById(
        "analyticsMessage"
    );

    message.textContent = "Loading analytics...";

    try {
        const response = await fetch("/api/analytics", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(
                "Analytics request failed: " + response.status
            );
        }

        const data = await response.json();

        if (typeof Chart === "undefined") {
            throw new Error(
                "Chart.js could not load. Check your internet connection."
            );
        }

        renderSeverityChart(data);
        renderAttackChart(data);
        renderActivityChart(data);
        renderInvestigationSummary(data);

        message.textContent =
            "Analytics updated successfully.";
    } catch (error) {
        message.textContent = error.message;
        console.error("AllamSec analytics error:", error);
    }
}

document.getElementById(
    "refreshAnalytics"
).addEventListener("click", loadAnalytics);

loadAnalytics();