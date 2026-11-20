// ==========================================================================
// NETSENTINEL OT: Modern Industrial Cybersecurity Dashboard Client
// Supports Dark / Light Theme, Animated Donut Chart, 8-Port Switch Visualizer,
// Dynamic Response Latency Chart, and Live Firewall IP Block / Unblock.
// ==========================================================================

document.addEventListener("DOMContentLoaded", () => {
  // -------------------------------------------------------------
  // 1. Elements Selection
  // -------------------------------------------------------------
  const htmlRoot = document.documentElement;
  const btnThemeToggle = document.getElementById("btn-theme-toggle");
  const themeIcon = document.getElementById("theme-icon");
  const btnFullscreen = document.getElementById("btn-fullscreen");

  // Status & Navbar
  const netSubnetText = document.getElementById("net-subnet-text");
  const ifaceDot = document.getElementById("iface-dot");
  const ifaceStatusText = document.getElementById("iface-status-text");
  const adminPill = document.getElementById("admin-pill");
  const adminDot = document.getElementById("admin-dot");
  const adminPillText = document.getElementById("admin-pill-text");
  const scanPillText = document.getElementById("scan-pill-text");
  const btnScan = document.getElementById("btn-scan");
  const scanIcon = document.getElementById("scan-icon");
  const disconnectBanner = document.getElementById("disconnect-banner");
  const disconnectTitle = document.getElementById("disconnect-title");
  const disconnectHelp = document.getElementById("disconnect-help");
  const scanTimeMeta = document.getElementById("scan-time-meta");

  // KPI Elements
  const numOnline = document.getElementById("num-online");
  const numPlc = document.getElementById("num-plc");
  const numSafe = document.getElementById("num-safe");
  const numWarn = document.getElementById("num-warn");
  const numBlocked = document.getElementById("num-blocked");
  const kpiWarnTrend = document.getElementById("kpi-warn-trend");
  const kpiBlockedTrend = document.getElementById("kpi-blocked-trend");

  // Donut Elements
  const donutTotalNum = document.getElementById("donut-total-num");
  const legSafeVal = document.getElementById("leg-safe-val");
  const legPlcVal = document.getElementById("leg-plc-val");
  const legWarnVal = document.getElementById("leg-warn-val");
  const legBlockedVal = document.getElementById("leg-blocked-val");
  const segSafe = document.getElementById("donut-segment-safe");
  const segPlc = document.getElementById("donut-segment-plc");
  const segWarn = document.getElementById("donut-segment-warn");
  const segBlocked = document.getElementById("donut-segment-blocked");

  // 8-Port Switch Visualizer Container
  const switchPortsContainer = document.getElementById("switch-ports-container");

  // Latency Column Bar Chart Container
  const latencyChartContainer = document.getElementById("latency-chart-container");
  const latencySummaryBadge = document.getElementById("latency-summary-badge");

  // Warning Banner
  const warningBanner = document.getElementById("warning-banner");
  const warningList = document.getElementById("warning-list");

  // Table & Filters
  const devicesTbody = document.getElementById("devices-tbody");
  const searchInput = document.getElementById("search-input");
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabCountOnline = document.getElementById("tab-count-online");
  const tabCountPlc = document.getElementById("tab-count-plc");
  const tabCountSwitch = document.getElementById("tab-count-switch");
  const tabCountWarn = document.getElementById("tab-count-warn");
  const tabCountSafe = document.getElementById("tab-count-safe");
  const tabCountBlocked = document.getElementById("tab-count-blocked");
  const tabCountOffline = document.getElementById("tab-count-offline");
  const btnClearHistory = document.getElementById("btn-clear-history");

  // Quick Whitelist Form
  const formQuickAdd = document.getElementById("form-quick-add");
  const manualIp = document.getElementById("manual-ip");
  const manualName = document.getElementById("manual-name");

  // -------------------------------------------------------------
  // 2. State
  // -------------------------------------------------------------
  let allDevices = [];
  let activeTab = "online";
  let searchQuery = "";
  let countdownSeconds = 10;
  let isScanningState = false;

  // -------------------------------------------------------------
  // 3. Theme Toggle (Dark Analytics vs Light Executive)
  // -------------------------------------------------------------
  const savedTheme = localStorage.getItem("netsentinel_theme") || "dark";
  setTheme(savedTheme);

  btnThemeToggle.addEventListener("click", () => {
    const currentTheme = htmlRoot.getAttribute("data-theme") || "dark";
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
  });

  function setTheme(theme) {
    htmlRoot.setAttribute("data-theme", theme);
    localStorage.setItem("netsentinel_theme", theme);
    if (themeIcon) {
      themeIcon.textContent = theme === "dark" ? "Theme: Dark" : "Theme: Light";
    }
  }

  // Fullscreen Mode
  btnFullscreen.addEventListener("click", () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  });

  // -------------------------------------------------------------
  // 4. Helper Classification Functions
  // -------------------------------------------------------------
  function isPlcOrPi(d) {
    const t = (d.device_type || "").toLowerCase();
    const v = (d.vendor || "").toLowerCase();
    const h = (d.hostname || "").toLowerCase();
    return t.includes("plc") || t.includes("raspberry") || t.includes("controller") || 
           v.includes("raspberry") || v.includes("siemens") || v.includes("schneider") || 
           v.includes("rockwell") || v.includes("omron") || h.includes("raspberry") || h.includes("plc");
  }

  function isSwitchDevice(d) {
    const t = (d.device_type || "").toLowerCase();
    const v = (d.vendor || "").toLowerCase();
    return t.includes("switch") || t.includes("gateway") || v.includes("switch") || v.includes("moxa") || v.includes("hirschmann") || d.is_switch;
  }

  // -------------------------------------------------------------
  // 5. Data Fetching & Core Dashboard Update
  // -------------------------------------------------------------
  async function loadData() {
    try {
      const [status, devices] = await Promise.all([
        fetch("/api/status").then(r => r.json()),
        fetch("/api/devices").then(r => r.json())
      ]);

      // Strict client-side filter: drop any non-Ethernet or Wi-Fi IP (172.x.x.x)
      allDevices = devices.filter(d => !d.ip_address.startsWith("172."));

      updateDashboard(status);
    } catch (e) {
      console.error("Dashboard data load error:", e);
    }
  }

  function updateDashboard(status) {
    // 1. Update Top Interface Banner
    if (status.is_connected) {
      netSubnetText.textContent = `OT Interface: ${status.interface_name} [Index: ${status.interface_index}] | Station IP: ${status.local_ip} | Subnet: ${status.subnet} (${status.adapter_description || 'Realtek GbE'})`;
      if (ifaceDot) ifaceDot.className = "dot dot-green";
      if (ifaceStatusText) ifaceStatusText.textContent = `Ethernet (Index ${status.interface_index}) Connected`;
      disconnectBanner.style.display = "none";
    } else {
      netSubnetText.innerHTML = `<span style="color: #ef4444; font-weight: bold;">⚠️ OT Network Offline: Ethernet Cable Unplugged</span>`;
      if (ifaceDot) ifaceDot.className = "dot dot-red";
      if (ifaceStatusText) ifaceStatusText.textContent = "Ethernet Disconnected";
      disconnectBanner.style.display = "block";
      if (status.error_message) disconnectHelp.textContent = status.error_message;
    }

    // 2. Firewall Admin Privilege Status Indicator
    if (adminPill && adminPillText) {
      if (status.is_admin) {
        if (adminDot) adminDot.className = "dot dot-green";
        adminPillText.textContent = "🛡️ Firewall: Active (Admin)";
        adminPill.title = "Running with Administrator privileges. Live dynamic Windows Firewall blocking is active.";
      } else {
        if (adminDot) adminDot.className = "dot dot-red";
        adminPillText.textContent = "⚠️ Firewall: Run as Admin";
        adminPill.title = "Application running non-elevated. Launch via 'start_admin.bat' for live Windows Firewall IP blocking.";
      }
    }

    // 3. Scan Indicator & Metadata
    if (status.last_scan_timestamp) {
      scanTimeMeta.textContent = `Last scan: ${status.last_scan_timestamp}`;
    }

    isScanningState = status.is_scanning;
    if (status.is_scanning) {
      scanPillText.textContent = "Scanning OT Ethernet...";
      scanIcon.style.animation = "spin 1s infinite linear";
      btnScan.disabled = true;
    } else {
      scanPillText.textContent = `Auto-scan in ${countdownSeconds}s`;
      scanIcon.style.animation = "none";
      btnScan.disabled = false;
    }

    // 4. Categorize Device Subsets
    const onlineDevs = allDevices.filter(d => d.status === "ONLINE");
    const plcDevs = onlineDevs.filter(d => isPlcOrPi(d));
    const switchDevs = onlineDevs.filter(d => isSwitchDevice(d));
    const offlineDevs = allDevices.filter(d => d.status === "OFFLINE");
    const warnDevs = onlineDevs.filter(d => !d.is_authorized);
    const safeDevs = allDevices.filter(d => d.is_authorized);
    const blockedDevs = allDevices.filter(d => d.is_blocked);

    // 5. Update KPI Cards
    numOnline.textContent = onlineDevs.length;
    if (numPlc) numPlc.textContent = plcDevs.length;
    numSafe.textContent = safeDevs.length;
    numWarn.textContent = warnDevs.length;
    if (numBlocked) numBlocked.textContent = blockedDevs.length;

    if (kpiWarnTrend) {
      kpiWarnTrend.textContent = warnDevs.length === 0 ? "0 Strangers" : `⚠️ ${warnDevs.length} Rogue!`;
      kpiWarnTrend.className = warnDevs.length === 0 ? "kpi-trend trend-positive" : "kpi-trend trend-warn";
    }

    if (kpiBlockedTrend) {
      kpiBlockedTrend.textContent = blockedDevs.length > 0 ? `${blockedDevs.length} Dropped` : "0 Blocked";
    }

    // 6. Update Tab Counts
    tabCountOnline.textContent = onlineDevs.length;
    if (tabCountPlc) tabCountPlc.textContent = plcDevs.length;
    if (tabCountSwitch) tabCountSwitch.textContent = switchDevs.length;
    tabCountWarn.textContent = warnDevs.length;
    tabCountSafe.textContent = safeDevs.length;
    if (tabCountBlocked) tabCountBlocked.textContent = blockedDevs.length;
    tabCountOffline.textContent = offlineDevs.length;

    // 7. Render Visual Hub (Donut, Switch Visualizer, Latency Bar Chart)
    renderDonutChart(onlineDevs, safeDevs, plcDevs, warnDevs, blockedDevs);
    renderSwitchVisualizer(onlineDevs, blockedDevs, status.local_ip);
    renderLatencyBarChart(onlineDevs);

    // 8. Render Warning Banner & Table
    renderWarningBanner(warnDevs);
    renderTable();
  }

  // -------------------------------------------------------------
  // 6. Graphical Animation 1: Animated SVG Donut Chart
  // -------------------------------------------------------------
  function renderDonutChart(onlineDevs, safeDevs, plcDevs, warnDevs, blockedDevs) {
    const total = onlineDevs.length;
    donutTotalNum.textContent = total;

    const safeCount = safeDevs.filter(d => d.status === "ONLINE").length;
    const plcCount = plcDevs.length;
    const warnCount = warnDevs.length;
    const blockedCount = blockedDevs.filter(d => d.status === "ONLINE").length;

    legSafeVal.textContent = safeCount;
    legPlcVal.textContent = plcCount;
    legWarnVal.textContent = warnCount;
    legBlockedVal.textContent = blockedCount;

    // Circumference of r=62 is 2 * PI * 62 = 389.56
    const C = 2 * Math.PI * 62;

    if (total === 0) {
      [segSafe, segPlc, segWarn, segBlocked].forEach(el => {
        if (el) {
          el.style.strokeDasharray = `0 ${C}`;
          el.style.strokeDashoffset = "0";
        }
      });
      return;
    }

    // Calculate proportional stroke lengths
    const lenSafe = (safeCount / total) * C;
    const lenPlc = (plcCount / total) * C;
    const lenWarn = (warnCount / total) * C;
    const lenBlocked = (blockedCount / total) * C;

    let offset = 0;

    if (segSafe) {
      segSafe.style.strokeDasharray = `${lenSafe} ${C}`;
      segSafe.style.strokeDashoffset = `${-offset}`;
      offset += lenSafe;
    }
    if (segPlc) {
      segPlc.style.strokeDasharray = `${lenPlc} ${C}`;
      segPlc.style.strokeDashoffset = `${-offset}`;
      offset += lenPlc;
    }
    if (segWarn) {
      segWarn.style.strokeDasharray = `${lenWarn} ${C}`;
      segWarn.style.strokeDashoffset = `${-offset}`;
      offset += lenWarn;
    }
    if (segBlocked) {
      segBlocked.style.strokeDasharray = `${lenBlocked} ${C}`;
      segBlocked.style.strokeDashoffset = `${-offset}`;
    }
  }

  // -------------------------------------------------------------
  // 7. Graphical Animation 2: Physical 8-Port Switch Visualizer
  // -------------------------------------------------------------
  function renderSwitchVisualizer(onlineDevs, blockedDevs, localIp) {
    if (!switchPortsContainer) return;

    // Map active devices to ports 1 through 8
    // Port 1 is designated for the Host Station (192.168.0.12)
    // Other devices take consecutive ports
    const portMapping = new Array(8).fill(null);

    // Host station goes to Port 1
    const hostDev = onlineDevs.find(d => d.ip_address === localIp);
    const otherDevs = onlineDevs.filter(d => d.ip_address !== localIp);

    if (hostDev) {
      portMapping[0] = { ...hostDev, isHost: true };
    } else {
      portMapping[0] = { ip_address: localIp || "192.168.0.12", hostname: "BALA (OT Host)", isHost: true, status: "ONLINE" };
    }

    // Other devices populate ports 2 through 8
    let nextSlot = 1;
    for (const dev of otherDevs) {
      if (nextSlot < 8) {
        portMapping[nextSlot] = dev;
        nextSlot++;
      }
    }

    let portsHtml = "";
    for (let i = 0; i < 8; i++) {
      const portNum = i + 1;
      const dev = portMapping[i];
      const isPlugged = dev !== null;
      const isBlk = dev && dev.is_blocked;
      const isHost = dev && dev.isHost;

      const portClass = isPlugged 
        ? (isBlk ? "rj45-port-module port-active port-blocked" : (isHost ? "rj45-port-module port-active port-host" : "rj45-port-module port-active"))
        : "rj45-port-module";

      let linkLed = '<span class="led-dot led-grey"></span>';
      let actLed = '<span class="led-dot led-grey"></span>';

      if (isPlugged) {
        if (isBlk) {
          linkLed = '<span class="led-dot led-red"></span>';
          actLed = '<span class="led-dot led-red"></span>';
        } else {
          linkLed = '<span class="led-dot led-green"></span>';
          actLed = '<span class="led-dot led-amber-blink"></span>';
        }
      }

      const ipLabel = isPlugged 
        ? (isHost ? "Host (P1)" : dev.ip_address) 
        : `Port ${portNum}`;

      const titleAttr = isPlugged 
        ? `Port ${portNum}: ${dev.ip_address} (${dev.hostname || 'Device'}) - ${isBlk ? 'BLOCKED' : 'ONLINE'}`
        : `Port ${portNum}: Empty / Link Down`;

      portsHtml += `
        <div class="${portClass}" title="${titleAttr}" data-ip="${isPlugged ? dev.ip_address : ''}">
          <div class="port-header">
            <span class="port-num">P${portNum}</span>
            <div class="port-leds-row">
              ${linkLed}
              ${actLed}
            </div>
          </div>
          <div class="rj45-jack-socket">
            <div class="rj45-pins"></div>
            <div class="rj45-clip-notch"></div>
          </div>
          <span class="port-ip-label">${ipLabel}</span>
        </div>
      `;
    }

    switchPortsContainer.innerHTML = portsHtml;

    // Click on port to filter search box
    switchPortsContainer.querySelectorAll(".rj45-port-module").forEach(p => {
      p.onclick = () => {
        const ip = p.getAttribute("data-ip");
        if (ip) {
          searchInput.value = ip;
          searchQuery = ip;
          renderTable();
          searchInput.focus();
        }
      };
    });
  }

  // -------------------------------------------------------------
  // 8. Graphical Animation 3: Latency & Response Column Bar Chart
  // -------------------------------------------------------------
  function renderLatencyBarChart(onlineDevs) {
    if (!latencyChartContainer) return;

    if (onlineDevs.length === 0) {
      latencyChartContainer.innerHTML = `<div style="margin: auto; color: var(--text-muted); font-size: 11px;">Waiting for active OT switch devices...</div>`;
      return;
    }

    let barsHtml = "";
    for (const dev of onlineDevs) {
      const isBlk = dev.is_blocked;
      const isPi = isPlcOrPi(dev);

      // Latency calculation: simulated 1-3ms or 0ms if blocked
      let msVal = 1;
      let barClass = "bar-pill bar-emerald";
      let tooltipText = `${dev.ip_address}: 1ms (Active)`;

      if (isBlk) {
        msVal = 0.2;
        barClass = "bar-pill bar-blocked";
        tooltipText = `${dev.ip_address}: DROPPED (Firewall Blocked)`;
      } else if (isPi) {
        msVal = 2;
        barClass = "bar-pill";
        tooltipText = `${dev.ip_address}: 2ms (PLC / Controller)`;
      }

      // Height proportional (max 100px)
      const heightPx = isBlk ? 15 : (msVal === 1 ? 65 : 95);

      barsHtml += `
        <div class="bar-col-item" data-ip="${dev.ip_address}">
          <div class="bar-tooltip">${tooltipText}</div>
          <div class="${barClass}" style="height: ${heightPx}px;"></div>
          <span class="bar-label-ip">${dev.ip_address.split('.').slice(2).join('.')}</span>
        </div>
      `;
    }

    latencyChartContainer.innerHTML = barsHtml;

    if (latencySummaryBadge) {
      const hasBlocked = onlineDevs.some(d => d.is_blocked);
      latencySummaryBadge.textContent = hasBlocked ? "Firewall Dropping Active" : "< 2ms OT Switch Average";
      latencySummaryBadge.className = hasBlocked ? "badge badge-warn" : "badge badge-subtle";
    }
  }

  // -------------------------------------------------------------
  // 9. Render Warning Banner (For LIVE Unknown Devices)
  // -------------------------------------------------------------
  function renderWarningBanner(liveUnknownDevices) {
    if (!warningBanner || !warningList) return;

    if (liveUnknownDevices.length === 0) {
      warningBanner.style.display = "none";
      warningList.innerHTML = "";
      return;
    }

    warningBanner.style.display = "block";
    let html = "";
    for (const d of liveUnknownDevices) {
      const roleText = isPlcOrPi(d) ? "⚙️ Industrial Controller" : (isSwitchDevice(d) ? "🔀 Network Switch" : "Unknown Device");
      html += `
        <div class="warn-card">
          <div class="warn-card-ip">${d.ip_address}</div>
          <div class="warn-card-meta">
            <div><strong>Host:</strong> ${d.hostname || 'Unknown OT Device'}</div>
            <div><strong>Role:</strong> ${roleText}</div>
            <div><strong>Vendor:</strong> ${d.vendor || 'N/A'}</div>
            <div><strong>MAC:</strong> ${d.mac_address || 'N/A'}</div>
            <div style="color: var(--accent-emerald); font-weight: bold;">🟢 Responding Active on Physical Ethernet Switch</div>
          </div>
          <div class="warn-card-actions">
            <button class="btn btn-sm btn-safe btn-action-trust" data-ip="${d.ip_address}" data-mac="${d.mac_address || ''}" data-name="${d.hostname || ''}">
              ✔ Whitelist OT Device
            </button>
            ${d.is_blocked 
              ? `<button class="btn btn-sm btn-primary btn-action-unblock" data-ip="${d.ip_address}">🔓 Unblock IP</button>` 
              : `<button class="btn btn-sm btn-danger btn-action-block" data-ip="${d.ip_address}">🚫 Block IP</button>`}
          </div>
        </div>
      `;
    }

    warningList.innerHTML = html;
    bindTableActions(warningList);
  }

  // -------------------------------------------------------------
  // 10. Render Devices Table
  // -------------------------------------------------------------
  function renderTable() {
    let filtered = allDevices;

    // Filter by Tab
    if (activeTab === "online") {
      filtered = filtered.filter(d => d.status === "ONLINE");
    } else if (activeTab === "plc") {
      filtered = filtered.filter(d => isPlcOrPi(d));
    } else if (activeTab === "switch") {
      filtered = filtered.filter(d => isSwitchDevice(d));
    } else if (activeTab === "warn") {
      filtered = filtered.filter(d => d.status === "ONLINE" && !d.is_authorized);
    } else if (activeTab === "safe") {
      filtered = filtered.filter(d => d.is_authorized);
    } else if (activeTab === "blocked") {
      filtered = filtered.filter(d => d.is_blocked);
    } else if (activeTab === "offline") {
      filtered = filtered.filter(d => d.status === "OFFLINE");
    }

    // Filter by Search Query
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(d => 
        (d.ip_address && d.ip_address.toLowerCase().includes(q)) ||
        (d.mac_address && d.mac_address.toLowerCase().includes(q)) ||
        (d.hostname && d.hostname.toLowerCase().includes(q)) ||
        (d.vendor && d.vendor.toLowerCase().includes(q)) ||
        (d.device_type && d.device_type.toLowerCase().includes(q))
      );
    }

    if (filtered.length === 0) {
      devicesTbody.innerHTML = `<tr><td colspan="10" class="empty-cell" style="text-align: center; padding: 24px; color: var(--text-muted);">No OT devices found matching current filters.</td></tr>`;
      return;
    }

    let rows = "";
    for (const d of filtered) {
      const isOnline = d.status === "ONLINE";
      const isAuth = d.is_authorized;
      const isBlk = d.is_blocked;
      const isPi = isPlcOrPi(d);
      const isSw = isSwitchDevice(d);

      // Device Role Badge
      let roleBadge = "";
      if (isPi) {
        const label = (d.vendor || "").includes("Raspberry") ? "⚙️ Raspberry Pi" : "🏭 Industrial PLC";
        roleBadge = `<span class="badge badge-plc">${label}</span>`;
      } else if (isSw) {
        roleBadge = `<span class="badge badge-switch">🔀 OT Switch</span>`;
      } else if ((d.device_type || "").includes("Workstation")) {
        roleBadge = `<span class="badge badge-host">💻 OT Workstation</span>`;
      } else {
        roleBadge = `<span class="badge" style="background: var(--bg-card-subtle); color: var(--text-secondary); border: 1px solid var(--border-subtle);">${d.device_type || 'OT Connected Device'}</span>`;
      }

      // Online State Badge
      const onlineBadge = isOnline 
        ? `<span class="badge badge-safe">🟢 Active Now</span>` 
        : `<span class="badge" style="background: var(--bg-card-subtle); color: var(--text-dim); border: 1px solid var(--border-subtle);">🕒 Disconnected</span>`;

      // Whitelist Status Badge
      const authBadge = isAuth 
        ? `<span class="badge badge-safe">✔ Whitelisted</span>` 
        : (isOnline ? `<span class="badge badge-warn">⚠️ Warning: Rogue</span>` : `<span class="badge" style="color: var(--text-dim);">Not Whitelisted</span>`);

      // Firewall Badge
      const fwBadge = isBlk 
        ? `<span class="badge badge-blocked">🚫 Blocked (Traffic Dropped)</span>` 
        : `<span style="color: var(--text-dim); font-size: 11px;">Normal</span>`;

      // Actions Buttons
      let actions = "";
      if (!isAuth) {
        actions += `<button class="btn btn-sm btn-safe btn-action-trust" data-ip="${d.ip_address}" data-mac="${d.mac_address || ''}" data-name="${d.hostname || ''}">✔ Whitelist</button>`;
      } else {
        actions += `<button class="btn btn-sm btn-secondary btn-action-revoke" data-ip="${d.ip_address}">Revoke</button>`;
      }

      if (isBlk) {
        actions += `<button class="btn btn-sm btn-primary btn-action-unblock" data-ip="${d.ip_address}">Unblock</button>`;
      } else {
        actions += `<button class="btn btn-sm btn-danger btn-action-block" data-ip="${d.ip_address}">Block</button>`;
      }

      if (!isOnline) {
        actions += `<button class="btn btn-sm btn-secondary btn-action-del" data-ip="${d.ip_address}" title="Delete from history">✕</button>`;
      }

      rows += `
        <tr class="${(isOnline && !isAuth) ? 'row-warn' : ''}">
          <td class="ip-text">${d.ip_address}</td>
          <td class="mac-text">${d.mac_address || 'N/A'}</td>
          <td><strong>${d.hostname || 'Unknown OT Device'}</strong></td>
          <td>${roleBadge}</td>
          <td><span class="vendor-text">${d.vendor || 'Generic OT Device'}</span></td>
          <td><span class="iface-tag">Ethernet (Index 9)</span></td>
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
  // 11. Button Actions (Trust, Revoke, Block, Unblock, Delete)
  // -------------------------------------------------------------
  function bindTableActions(container) {
    // 1. Whitelist / Trust
    container.querySelectorAll(".btn-action-trust").forEach(btn => {
      btn.onclick = async () => {
        const ip = btn.getAttribute("data-ip");
        const mac = btn.getAttribute("data-mac");
        const name = btn.getAttribute("data-name") || "Trusted OT Device";
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
        if (!confirm(`Revoke whitelist for OT device ${ip}?`)) return;
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
            body: JSON.stringify({ ip, reason: "Blocked from OT dashboard" })
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
        btn.textContent = "Unblocking...";
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

  // -------------------------------------------------------------
  // 12. Filters, Search & Countdown Polling Loop
  // -------------------------------------------------------------
  // Tab Switching
  tabBtns.forEach(btn => {
    btn.onclick = () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeTab = btn.getAttribute("data-tab");
      renderTable();
    };
  });

  // Instant Search Box
  searchInput.addEventListener("input", (e) => {
    searchQuery = e.target.value.trim();
    renderTable();
  });

  // Manual Scan Button Trigger
  btnScan.addEventListener("click", async () => {
    btnScan.disabled = true;
    scanIcon.style.animation = "spin 1s infinite linear";
    scanPillText.textContent = "Triggering scan...";
    try {
      await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ active_sweep: true })
      });
      countdownSeconds = 10;
      setTimeout(loadData, 1200);
    } catch (e) {
      console.error(e);
    }
  });

  // Clear Offline History
  btnClearHistory.addEventListener("click", async () => {
    if (!confirm("Remove all disconnected past devices from database history?")) return;
    try {
      const res = await fetch("/api/clear_offline", { method: "POST" }).then(r => r.json());
      alert(`Cleared ${res.deleted_count || 0} offline devices.`);
      loadData();
    } catch (e) {
      alert("Error: " + e.message);
    }
  });

  // Quick Manual Whitelist Add Form
  formQuickAdd.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ip = manualIp.value.trim();
    const name = manualName.value.trim() || "Authorized OT Device";
    if (!ip) return;
    try {
      await fetch("/api/authorize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, name })
      });
      manualIp.value = "";
      manualName.value = "";
      alert(`IP ${ip} has been added to authorized whitelist.`);
      loadData();
    } catch (err) {
      alert("Error: " + err.message);
    }
  });

  // Periodic Polling & Auto-Scan Countdown
  loadData();
  setInterval(() => {
    countdownSeconds--;
    if (countdownSeconds <= 0) {
      countdownSeconds = 10;
      loadData();
    } else {
      if (!isScanningState && scanPillText) {
        scanPillText.textContent = `Auto-scan in ${countdownSeconds}s`;
      }
    }
  }, 1000);
});
