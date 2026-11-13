// NetSentinel: Real-Time Scanner with 10s Cycle and Past History Management
document.addEventListener("DOMContentLoaded", () => {
  // Stat Elements
  const numOnline = document.getElementById("num-online");
  const numSafe = document.getElementById("num-safe");
  const numWarn = document.getElementById("num-warn");
  const numOffline = document.getElementById("num-offline");
  const boxWarningStat = document.getElementById("box-warning-stat");

  const netSubnetText = document.getElementById("net-subnet-text");
  const scanTimeMeta = document.getElementById("scan-time-meta");
  const btnScan = document.getElementById("btn-scan");
  const scanIcon = document.getElementById("scan-icon");
  const scanPillText = document.getElementById("scan-pill-text");

  // Warning Banner
  const warningBanner = document.getElementById("warning-banner");
  const warningList = document.getElementById("warning-list");

  // Table & Filters
  const devicesTbody = document.getElementById("devices-tbody");
  const searchInput = document.getElementById("search-input");
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabCountOnline = document.getElementById("tab-count-online");
  const tabCountWarn = document.getElementById("tab-count-warn");
  const tabCountSafe = document.getElementById("tab-count-safe");
  const tabCountOffline = document.getElementById("tab-count-offline");
  const btnClearHistory = document.getElementById("btn-clear-history");

  // Quick Add Form
  const formQuickAdd = document.getElementById("form-quick-add");
  const manualIp = document.getElementById("manual-ip");
  const manualName = document.getElementById("manual-name");

  // State
  let allDevices = [];
  let activeTab = "online";
  let searchQuery = "";
  let countdownSeconds = 10;

  // -------------------------------------------------------------
  // Data Fetching & UI Update
  // -------------------------------------------------------------

  async function loadData() {
    try {
      const [status, devices] = await Promise.all([
        fetch("/api/status").then(r => r.json()),
        fetch("/api/devices").then(r => r.json())
      ]);

      allDevices = devices;

      // Update Subnet & Wi-Fi state
      if (!status.is_connected) {
        netSubnetText.innerHTML = `<span style="color: #ef4444; font-weight: bold;">⚠️ Wi-Fi / Ethernet Disconnected (No Active Network)</span>`;
      } else if (status.local_ip && status.subnet) {
        netSubnetText.textContent = `Subnet: ${status.subnet} | Host IP: ${status.local_ip}`;
      }

      if (status.last_scan_timestamp) {
        scanTimeMeta.textContent = `Last scan: ${status.last_scan_timestamp}`;
      }

      // Scanner Status
      if (status.is_scanning) {
        scanPillText.textContent = "Scanning active IPs...";
        scanIcon.style.animation = "spin 1s infinite linear";
        btnScan.disabled = true;
      } else {
        scanPillText.textContent = `Auto-scan in ${countdownSeconds}s (10s cycle)`;
        scanIcon.style.animation = "none";
        btnScan.disabled = false;
      }

      // Categorize Devices
      const onlineDevs = allDevices.filter(d => d.status === "ONLINE");
      const offlineDevs = allDevices.filter(d => d.status === "OFFLINE");
      const warnDevs = onlineDevs.filter(d => !d.is_authorized);
      const safeDevs = allDevices.filter(d => d.is_authorized);

      numOnline.textContent = onlineDevs.length;
      numSafe.textContent = safeDevs.length;
      numWarn.textContent = warnDevs.length;
      numOffline.textContent = offlineDevs.length;

      tabCountOnline.textContent = onlineDevs.length;
      tabCountWarn.textContent = warnDevs.length;
      tabCountSafe.textContent = safeDevs.length;
      tabCountOffline.textContent = offlineDevs.length;

      if (warnDevs.length > 0) {
        boxWarningStat.classList.add("active-alert");
      } else {
        boxWarningStat.classList.remove("active-alert");
      }

      // Render Warning Banner (ONLY for CURRENTLY ONLINE unknown devices!)
      renderWarningBanner(warnDevs);
      renderTable();
    } catch (e) {
      console.error("Poll error:", e);
    }
  }

  // -------------------------------------------------------------
  // Render Warning Banner (Only for LIVE ONLINE unauthorized devices)
  // -------------------------------------------------------------

  function renderWarningBanner(liveUnknownDevices) {
    if (liveUnknownDevices.length === 0) {
      warningBanner.style.display = "none";
      warningList.innerHTML = "";
      return;
    }

    warningBanner.style.display = "block";
    let html = "";

    for (const d of liveUnknownDevices) {
      html += `
        <div class="warn-card">
          <div class="warn-card-ip">${d.ip_address}</div>
          <div class="warn-card-meta">
            <div><strong>Host:</strong> ${d.hostname || 'Unknown Device'}</div>
            <div><strong>MAC:</strong> ${d.mac_address || 'N/A'}</div>
            <div style="color: #10b981; font-weight: bold;">🟢 Responding Active Right Now</div>
          </div>
          <div class="warn-card-actions">
            <button class="btn btn-sm btn-safe btn-action-trust" data-ip="${d.ip_address}" data-mac="${d.mac_address || ''}" data-name="${d.hostname || ''}">
              ✔ Trust / Authorize
            </button>
            <button class="btn btn-sm btn-danger btn-action-block" data-ip="${d.ip_address}">
              🚫 Block IP
            </button>
          </div>
        </div>
      `;
    }

    warningList.innerHTML = html;
    bindTableActions(warningList);
  }

  // -------------------------------------------------------------
  // Render Devices Table
  // -------------------------------------------------------------

  function renderTable() {
    let filtered = allDevices;

    // Filter by Tab
    if (activeTab === "online") {
      filtered = filtered.filter(d => d.status === "ONLINE");
    } else if (activeTab === "warn") {
      filtered = filtered.filter(d => d.status === "ONLINE" && !d.is_authorized);
    } else if (activeTab === "safe") {
      filtered = filtered.filter(d => d.is_authorized);
    } else if (activeTab === "offline") {
      filtered = filtered.filter(d => d.status === "OFFLINE");
    }

    // Filter by Search Box
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(d => 
        (d.ip_address && d.ip_address.toLowerCase().includes(q)) ||
        (d.mac_address && d.mac_address.toLowerCase().includes(q)) ||
        (d.hostname && d.hostname.toLowerCase().includes(q))
      );
    }

    if (filtered.length === 0) {
      devicesTbody.innerHTML = `<tr><td colspan="7" class="empty-cell">No devices found in this category.</td></tr>`;
      return;
    }

    let rows = "";
    for (const d of filtered) {
      const isOnline = d.status === "ONLINE";
      const isAuth = d.is_authorized;
      const isBlk = d.is_blocked;

      // Online State Badge
      const onlineBadge = isOnline 
        ? `<span class="badge badge-safe">🟢 Active Now</span>` 
        : `<span class="badge" style="background: rgba(148, 163, 184, 0.1); color: #94a3b8;">🕒 Disconnected</span>`;

      // Whitelist Status Badge
      const authBadge = isAuth 
        ? `<span class="badge badge-safe">✔ Trusted (Safe)</span>` 
        : (isOnline ? `<span class="badge badge-warn">⚠️ Warning: Unknown</span>` : `<span class="badge" style="color: #64748b;">Not in Whitelist</span>`);

      // Firewall Badge
      const fwBadge = isBlk 
        ? `<span class="badge badge-blocked">🚫 Blocked</span>` 
        : `<span style="color: #64748b; font-size: 11px;">Normal</span>`;

      let actions = "";
      if (!isAuth) {
        actions += `<button class="btn btn-sm btn-safe btn-action-trust" data-ip="${d.ip_address}" data-mac="${d.mac_address || ''}" data-name="${d.hostname || ''}">✔ Trust</button>`;
      } else {
        actions += `<button class="btn btn-sm btn-secondary btn-action-revoke" data-ip="${d.ip_address}">Revoke</button>`;
      }

      if (isBlk) {
        actions += `<button class="btn btn-sm btn-primary btn-action-unblock" data-ip="${d.ip_address}">Unblock</button>`;
      } else {
        actions += `<button class="btn btn-sm btn-danger btn-action-block" data-ip="${d.ip_address}">Block</button>`;
      }

      // If device is offline, allow deleting from past history
      if (!isOnline) {
        actions += `<button class="btn btn-sm btn-secondary btn-action-del" data-ip="${d.ip_address}" title="Delete from history">✕</button>`;
      }

      rows += `
        <tr class="${(isOnline && !isAuth) ? 'row-warn' : ''}">
          <td class="ip-text">${d.ip_address}</td>
          <td class="mac-text">${d.mac_address || 'N/A'}</td>
          <td><strong>${d.hostname || 'Unknown Device'}</strong></td>
          <td>${onlineBadge}</td>
          <td>${authBadge}</td>
          <td>${fwBadge}</td>
          <td>
            <div class="action-btns">${actions}</div>
          </td>
        </tr>
      `;
    }

    devicesTbody.innerHTML = rows;
    bindTableActions(devicesTbody);
  }

  // -------------------------------------------------------------
  // Button Actions (Trust, Revoke, Block, Unblock, Delete)
  // -------------------------------------------------------------

  function bindTableActions(container) {
    // 1. Trust / Authorize
    container.querySelectorAll(".btn-action-trust").forEach(btn => {
      btn.onclick = async () => {
        const ip = btn.getAttribute("data-ip");
        const mac = btn.getAttribute("data-mac");
        const name = btn.getAttribute("data-name") || "Trusted Device";
        btn.disabled = true;
        btn.textContent = "Saving...";
        try {
          await fetch("/api/authorize", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip, mac, name })
          });
          loadData();
        } catch (e) {
          alert("Error: " + e.message);
        }
      };
    });

    // 2. Revoke Trust
    container.querySelectorAll(".btn-action-revoke").forEach(btn => {
      btn.onclick = async () => {
        const ip = btn.getAttribute("data-ip");
        if (!confirm(`Revoke trust for ${ip}?`)) return;
        btn.disabled = true;
        try {
          await fetch("/api/deauthorize", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip })
          });
          loadData();
        } catch (e) {
          alert("Error: " + e.message);
        }
      };
    });

    // 3. Block IP
    container.querySelectorAll(".btn-action-block").forEach(btn => {
      btn.onclick = async () => {
        const ip = btn.getAttribute("data-ip");
        if (!confirm(`Block IP ${ip} on Windows Firewall?`)) return;
        btn.disabled = true;
        btn.textContent = "Blocking...";
        try {
          const res = await fetch("/api/block", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip, reason: "Blocked from dashboard" })
          }).then(r => r.json());
          alert(res.message);
          loadData();
        } catch (e) {
          alert("Error: " + e.message);
        }
      };
    });

    // 4. Unblock IP
    container.querySelectorAll(".btn-action-unblock").forEach(btn => {
      btn.onclick = async () => {
        const ip = btn.getAttribute("data-ip");
        btn.disabled = true;
        try {
          const res = await fetch("/api/unblock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip })
          }).then(r => r.json());
          alert(res.message);
          loadData();
        } catch (e) {
          alert("Error: " + e.message);
        }
      };
    });

    // 5. Delete from Past History
    container.querySelectorAll(".btn-action-del").forEach(btn => {
      btn.onclick = async () => {
        const ip = btn.getAttribute("data-ip");
        try {
          await fetch("/api/delete_device", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip })
          });
          loadData();
        } catch (e) {
          alert("Error: " + e.message);
        }
      };
    });
  }

  // Clear All Past Offline History
  btnClearHistory.addEventListener("click", async () => {
    if (!confirm("Are you sure you want to remove all disconnected past devices from history?")) return;
    try {
      const res = await fetch("/api/clear_offline", { method: "POST" }).then(r => r.json());
      alert(`Cleared ${res.deleted_count || 0} offline devices from history.`);
      loadData();
    } catch (e) {
      alert("Error: " + e.message);
    }
  });

  // Search Box
  searchInput.addEventListener("input", (e) => {
    searchQuery = e.target.value.trim();
    renderTable();
  });

  // Filter Tabs
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeTab = btn.getAttribute("data-tab");
      renderTable();
    });
  });

  // Manual Scan Button
  btnScan.addEventListener("click", async () => {
    scanIcon.style.animation = "spin 1s infinite linear";
    btnScan.disabled = true;
    countdownSeconds = 10;
    try {
      await fetch("/api/scan", { method: "POST" });
      setTimeout(loadData, 1200);
    } catch (e) {
      console.error("Scan error:", e);
    }
  });

  // Quick Add Form
  formQuickAdd.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ip = manualIp.value.trim();
    const name = manualName.value.trim() || "Trusted Device";
    if (!ip) return;

    try {
      await fetch("/api/authorize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, name })
      });
      manualIp.value = "";
      manualName.value = "";
      alert(`IP ${ip} is now saved in MySQL Authorized Whitelist!`);
      loadData();
    } catch (err) {
      alert("Error: " + err.message);
    }
  });

  // Countdown timer ticker for 10-second cycles
  setInterval(() => {
    if (countdownSeconds > 1) {
      countdownSeconds--;
    } else {
      countdownSeconds = 10;
    }
    scanPillText.textContent = `Auto-scan in ${countdownSeconds}s (10s cycle)`;
  }, 1000);

  // Fullscreen Button
  const btnFullscreen = document.getElementById("btn-fullscreen");
  if (btnFullscreen) {
    btnFullscreen.addEventListener("click", () => {
      if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(() => {});
        btnFullscreen.innerHTML = "<span>🗗</span> Exit Fullscreen";
      } else {
        if (document.exitFullscreen) {
          document.exitFullscreen().catch(() => {});
        }
        btnFullscreen.innerHTML = "<span>⛶</span> Fullscreen";
      }
    });

    document.addEventListener("fullscreenchange", () => {
      if (!document.fullscreenElement) {
        btnFullscreen.innerHTML = "<span>⛶</span> Fullscreen";
      } else {
        btnFullscreen.innerHTML = "<span>🗗</span> Exit Fullscreen";
      }
    });
  }

  // Initial Data Load and Poll Loop every 2 seconds
  loadData();
  setInterval(loadData, 2000);
});
