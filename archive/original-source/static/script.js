let chart;
let alarmPlayed = false;

function levelClass(level) {
  const value = (level || "").toLowerCase();
  if (value.includes("normal")) return "normal";
  if (value.includes("low")) return "low";
  if (value.includes("medium")) return "medium";
  if (value.includes("high")) return "high";
  return "critical";
}

function updateTheme(level) {
  document.body.classList.remove("normal", "low", "medium", "high", "critical");
  document.body.classList.add(levelClass(level));
}

function renderEvents(events) {
  const list = document.getElementById("events-list");
  list.innerHTML = "";

  events.forEach(event => {
    const item = document.createElement("div");
    item.className = "event-item";

    const meta = document.createElement("div");
    meta.className = "event-meta";
    meta.innerHTML = `
      <strong>${event.title_en}</strong>
      <small>${event.time}</small>
    `;

    const level = document.createElement("div");
    level.className = "event-level";
    level.textContent = event.level;

    item.appendChild(meta);
    item.appendChild(level);
    list.appendChild(item);
  });
}

function initChart() {
  const ctx = document.getElementById("riskChart").getContext("2d");
  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: Array.from({ length: 12 }, (_, i) => `${i + 1}`),
      datasets: [{
        label: "Risk Score",
        data: [],
        borderWidth: 3,
        pointRadius: 4,
        pointHoverRadius: 6,
        tension: 0.35,
        fill: true
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        }
      },
      scales: {
        x: {
          ticks: { color: "#93a4bf" },
          grid: { color: "rgba(255,255,255,0.06)" }
        },
        y: {
          min: 0,
          max: 100,
          ticks: { color: "#93a4bf" },
          grid: { color: "rgba(255,255,255,0.06)" }
        }
      }
    }
  });
}

function chartColors(level) {
  const cls = levelClass(level);
  if (cls === "normal") return { border: "#00e676", fill: "rgba(0,230,118,0.18)" };
  if (cls === "low") return { border: "#2979ff", fill: "rgba(41,121,255,0.18)" };
  if (cls === "medium") return { border: "#ffea00", fill: "rgba(255,234,0,0.18)" };
  if (cls === "high") return { border: "#ff9100", fill: "rgba(255,145,0,0.18)" };
  return { border: "#ff1744", fill: "rgba(255,23,68,0.18)" };
}

function updateChart(level, history) {
  const colors = chartColors(level);
  chart.data.labels = history.map((_, i) => `${i + 1}`);
  chart.data.datasets[0].data = history;
  chart.data.datasets[0].borderColor = colors.border;
  chart.data.datasets[0].backgroundColor = colors.fill;
  chart.update();
}

function playAlarm() {
  const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  const frequencies = [880, 660, 880];

  let time = audioCtx.currentTime;

  frequencies.forEach(freq => {
    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();

    oscillator.type = "sine";
    oscillator.frequency.setValueAtTime(freq, time);

    gainNode.gain.setValueAtTime(0.0001, time);
    gainNode.gain.exponentialRampToValueAtTime(0.2, time + 0.02);
    gainNode.gain.exponentialRampToValueAtTime(0.0001, time + 0.28);

    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);

    oscillator.start(time);
    oscillator.stop(time + 0.3);

    time += 0.32;
  });
}

function handleCriticalAlarm(score, level) {
  const isCritical = levelClass(level) === "critical" && Number(score) >= 90;

  if (isCritical && !alarmPlayed) {
    playAlarm();
    alarmPlayed = true;
  }

  if (!isCritical) {
    alarmPlayed = false;
  }
}

function toggleTheme() {
  const body = document.body;
  if (body.classList.contains("light")) {
    body.classList.remove("light");
    body.classList.add("dark");
    localStorage.setItem("theme", "dark");
  } else {
    body.classList.remove("dark");
    body.classList.add("light");
    localStorage.setItem("theme", "light");
  }
}

function loadTheme() {
  const saved = localStorage.getItem("theme");
  if (saved === "light") {
    document.body.classList.remove("dark");
    document.body.classList.add("light");
  } else {
    document.body.classList.remove("light");
    document.body.classList.add("dark");
  }
}

async function fetchStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();

    document.getElementById("system-name-en").textContent = data.system_name_en;
    document.getElementById("last-update").textContent = data.last_update;
    document.getElementById("status-en").textContent = data.attack_type;
    document.getElementById("risk-score").textContent = data.risk_score;
    document.getElementById("confidence").textContent = `${data.confidence}%`;
    document.getElementById("alerts-count").textContent = data.alerts_count;
    document.getElementById("avg-risk").textContent = data.avg_risk;
    document.getElementById("probability").textContent = data.probability;
    document.getElementById("risk-level-chip").textContent = data.risk_level;
    document.getElementById("score-bar-fill").style.width = `${data.risk_score}%`;

    updateTheme(data.risk_level);
    updateChart(data.risk_level, data.history);
    renderEvents(data.events);
    handleCriticalAlarm(data.risk_score, data.risk_level);
  } catch (err) {}
}

window.addEventListener("DOMContentLoaded", async () => {
  loadTheme();
  const toggle = document.getElementById("theme-toggle");
  toggle.addEventListener("click", toggleTheme);
  initChart();
  await fetchStatus();
  setInterval(fetchStatus, 2000);
});
