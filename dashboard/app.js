let authToken = localStorage.getItem("fw_auth_token") || "";
let userRole = localStorage.getItem("fw_user_role") || "";
let userName = localStorage.getItem("fw_user_name") || "";

function updateAuthUI() {
  const display = document.getElementById("user-display");
  const btn = document.getElementById("auth-btn");
  if (authToken && userName) {
    display.textContent = userName + " (" + userRole + ")";
    btn.textContent = "Logout";
  } else {
    display.textContent = "Not Logged In";
    btn.textContent = "Login";
  }
}

function fetchWithAuth(url, options = {}) {
  options.headers = options.headers || {};
  if (authToken) {
    options.headers["X-Auth-Token"] = authToken;
  }
  return fetch(url, options);
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function refreshStats() {
  fetchWithAuth("/api/stats")
    .then(res => res.json())
    .then(data => {
      const m = data.metrics || {};
      document.getElementById("val-bytes").textContent = formatBytes(m.total_bytes || 0);
      document.getElementById("val-bps").textContent = formatBytes(m.bps || 0) + "/s";
      document.getElementById("val-packets").textContent = (m.total_packets || 0).toLocaleString();
      document.getElementById("val-pps").textContent = (m.pps || 0) + " pps";
      document.getElementById("val-dropped").textContent = (m.total_dropped || 0).toLocaleString();
      document.getElementById("val-dps").textContent = (m.drops_per_sec || 0) + " drops/s";
      document.getElementById("val-sessions").textContent = (m.active_sessions || 0).toLocaleString();

      if (data.license && data.license.tier) {
        document.getElementById("tier-badge").textContent = data.license.tier;
      }

      renderEvents(data.recent_events || []);
    })
    .catch(() => {});
}

function renderEvents(events) {
  const tbody = document.getElementById("events-body");
  if (!events || events.length === 0) {
    tbody.innerHTML = "<tr><td colspan='8' class='text-center'>No recent security events</td></tr>";
    return;
  }
  let html = "";
  events.forEach(e => {
    const actionClass = e.action_taken === "ALLOW" ? "tag-allow" : "tag-drop";
    html += "<tr>" +
      "<td>" + e.id + "</td>" +
      "<td>" + (e.timestamp || "") + "</td>" +
      "<td>" + e.source_ip + "</td>" +
      "<td>" + e.dest_ip + "</td>" +
      "<td>" + (e.dest_port || "-") + "</td>" +
      "<td>" + e.threat_type + "</td>" +
      "<td class='" + actionClass + "'>" + e.action_taken + "</td>" +
      "<td>" + (e.payload_sample || "").substring(0, 30) + "</td>" +
      "</tr>";
  });
  tbody.innerHTML = html;
}

function refreshRules() {
  fetchWithAuth("/api/rules")
    .then(res => res.json())
    .then(rules => {
      const tbody = document.getElementById("rules-body");
      if (!Array.isArray(rules) || rules.length === 0) {
        tbody.innerHTML = "<tr><td colspan='6' class='text-center'>No ACL rules defined</td></tr>";
        return;
      }
      let html = "";
      rules.forEach(r => {
        const actionClass = r.action === "ALLOW" ? "tag-allow" : "tag-drop";
        html += "<tr>" +
          "<td>" + r.priority + "</td>" +
          "<td class='" + actionClass + "'>" + r.action + "</td>" +
          "<td>" + r.protocol + "</td>" +
          "<td>" + r.source_cidr + "</td>" +
          "<td>" + (r.dest_port || "ANY") + "</td>" +
          "<td><button class='btn btn-sm btn-danger' onclick='deleteRule(" + r.id + ")'>Del</button></td>" +
          "</tr>";
      });
      tbody.innerHTML = html;
    })
    .catch(() => {});
}

function refreshBans() {
  fetchWithAuth("/api/bans")
    .then(res => res.json())
    .then(bans => {
      const tbody = document.getElementById("bans-body");
      if (!Array.isArray(bans) || bans.length === 0) {
        tbody.innerHTML = "<tr><td colspan='4' class='text-center'>No active bans</td></tr>";
        return;
      }
      let html = "";
      bans.forEach(b => {
        html += "<tr>" +
          "<td>" + b.ip_address + "</td>" +
          "<td>" + b.reason + "</td>" +
          "<td>" + (b.expires_at || "") + "</td>" +
          "<td><button class='btn btn-sm' onclick='unbanIp(\"" + b.ip_address + "\")'>Unban</button></td>" +
          "</tr>";
      });
      tbody.innerHTML = html;
    })
    .catch(() => {});
}

function deleteRule(ruleId) {
  fetchWithAuth("/api/rules/" + ruleId, { method: "DELETE" })
    .then(res => res.json())
    .then(res => {
      if (res.error) {
        alert(res.error);
      } else {
        refreshRules();
      }
    });
}

function unbanIp(ip) {
  fetchWithAuth("/api/bans/" + ip, { method: "DELETE" })
    .then(res => res.json())
    .then(res => {
      if (res.error) {
        alert(res.error);
      } else {
        refreshBans();
      }
    });
}

document.getElementById("btn-add-rule").addEventListener("click", () => {
  const payload = {
    priority: parseInt(document.getElementById("rf-priority").value, 10),
    action: document.getElementById("rf-action").value,
    direction: "INBOUND",
    protocol: "TCP",
    source_cidr: document.getElementById("rf-cidr").value,
    dest_cidr: "0.0.0.0/0",
    dest_port: document.getElementById("rf-port").value ? parseInt(document.getElementById("rf-port").value, 10) : null
  };
  fetchWithAuth("/api/rules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  })
    .then(res => res.json())
    .then(res => {
      if (res.error) {
        alert(res.error);
      } else {
        refreshRules();
      }
    });
});

document.getElementById("btn-add-ban").addEventListener("click", () => {
  const ip = document.getElementById("bf-ip").value;
  const dur = parseInt(document.getElementById("bf-duration").value, 10) || 300;
  if (!ip) return;
  fetchWithAuth("/api/bans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip_address: ip, duration: dur, reason: "Manual Operator Ban" })
  })
    .then(res => res.json())
    .then(res => {
      if (res.error) {
        alert(res.error);
      } else {
        document.getElementById("bf-ip").value = "";
        refreshBans();
      }
    });
});

document.getElementById("export-rules-btn").addEventListener("click", () => {
  window.open("/api/export/rules", "_blank");
});

document.getElementById("export-logs-btn").addEventListener("click", () => {
  window.open("/api/export/logs", "_blank");
});

const modal = document.getElementById("login-modal");
document.getElementById("auth-btn").addEventListener("click", () => {
  if (authToken) {
    fetchWithAuth("/api/auth/logout", { method: "POST" }).finally(() => {
      authToken = "";
      userRole = "";
      userName = "";
      localStorage.removeItem("fw_auth_token");
      localStorage.removeItem("fw_user_role");
      localStorage.removeItem("fw_user_name");
      updateAuthUI();
    });
  } else {
    modal.classList.remove("hidden");
  }
});

document.getElementById("close-modal").addEventListener("click", () => {
  modal.classList.add("hidden");
});

document.getElementById("login-submit").addEventListener("click", () => {
  const u = document.getElementById("login-username").value;
  const p = document.getElementById("login-password").value;
  const err = document.getElementById("login-err");
  err.textContent = "";

  fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: u, password: p })
  })
    .then(res => {
      if (!res.ok) throw new Error("Invalid username or password");
      return res.json();
    })
    .then(data => {
      authToken = data.token;
      userRole = data.role;
      userName = data.username;
      localStorage.setItem("fw_auth_token", authToken);
      localStorage.setItem("fw_user_role", userRole);
      localStorage.setItem("fw_user_name", userName);
      modal.classList.add("hidden");
      updateAuthUI();
      refreshStats();
      refreshRules();
      refreshBans();
    })
    .catch(e => {
      err.textContent = e.message;
    });
});

updateAuthUI();
refreshStats();
refreshRules();
refreshBans();
setInterval(refreshStats, 2000);

