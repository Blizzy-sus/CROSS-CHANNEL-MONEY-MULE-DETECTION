/* global d3 */
(function () {
  "use strict";

  const ATTACK_TYPES = {
    "fan-in": "#00c8ff",
    "fan-out": "#ff6600",
    "layering": "#4080ff",
    smurfing: "#00ff88",
    "shell-company": "#c040ff",
    "trade-based": "#00e0c0",
    "loan-back": "#ff40a0",
    "mule-chain": "#ff2020",
    structuring: "#ffe040",
    "rapid-cycling": "#ffffff",
  };

  const STATE_STROKE = {
    clean: "#1a3a55",
    monitoring: "#1a4070",
    suspicious: "#c87820",
    flagged: "#e85020",
    mule: "#e82020",
    source: "#2060d0",
    hub: "#9030d0",
    shell: "#b030a0",
    layer: "#2080c0",
    smurfing: "#20b060",
    confirmed: "#ff2020",
  };

  const state = {
    nodes: [],
    edges: [],
    attacks: [],
    attacksIdentified: 0,
    attackIndex: 0,
    metrics: {},
    hulls: {},
    activeFilter: "all",
    simulation: null,
    svg: null,
    width: 800,
    height: 600,
    tooltip: null,
    linkSel: null,
    nodeSel: null,
    hullG: null,
    pulseLayer: null,
  };

  function el(id) {
    return document.getElementById(id);
  }

  function wsUrl() {
    const p = location.protocol === "https:" ? "wss:" : "ws:";
    return p + "//" + location.host + "/ws/ledger";
  }

  class SentinelWS {
    constructor(url) {
      this.url = url;
      this.ws = null;
      this.reconnectDelay = 1200;
      this.handlers = {};
      this.connect();
    }

    connect() {
      try {
        this.ws = new WebSocket(this.url);
      } catch (e) {
        setTimeout(() => this.connect(), this.reconnectDelay);
        return;
      }
      this.ws.onmessage = (e) => {
        try {
          this.dispatch(JSON.parse(e.data));
        } catch (_) {}
      };
      this.ws.onclose = () => setTimeout(() => this.connect(), this.reconnectDelay);
      this.ws.onerror = () => {
        try {
          this.ws.close();
        } catch (_) {}
      };
    }

    on(type, fn) {
      this.handlers[type] = fn;
    }

    dispatch(event) {
      const t = event.type;
      if (this.handlers[t]) this.handlers[t](event);
    }
  }

  function nodeRadius(d) {
    const r = d.role || "standard";
    if (r === "hub") return 18;
    if (r === "source") return 14;
    if (r === "main") return 12;
    if (r === "micro") return 5;
    return 8;
  }

  function initThreatBar() {
    const bar = el("threatBar");
    bar.innerHTML = "";
    for (let i = 0; i < 10; i++) {
      const s = document.createElement("div");
      s.className = "threat-seg";
      s.dataset.i = String(i);
      bar.appendChild(s);
    }
  }

  function setThreatLevel(pct) {
    const n = Math.min(10, Math.max(0, Math.ceil(pct / 10)));
    const segs = el("threatBar").querySelectorAll(".threat-seg");
    segs.forEach((seg, i) => {
      seg.className = "threat-seg";
      if (i < n) {
        seg.classList.add("on");
        if (i < 3) seg.classList.add("low");
        else if (i < 6) seg.classList.add("med");
        else if (i < 9) seg.classList.add("high");
        else seg.classList.add("crit");
      }
    });
    const lab = el("threatLabel");
    if (n <= 3) lab.textContent = "THREAT: LOW";
    else if (n <= 6) lab.textContent = "THREAT: MEDIUM";
    else if (n <= 9) lab.textContent = "THREAT: HIGH";
    else lab.textContent = "THREAT: CRITICAL";
  }

  function initRiskSegments() {
    const rs = el("riskSegments");
    rs.innerHTML = "";
    for (let i = 0; i < 10; i++) {
      const s = document.createElement("span");
      s.dataset.i = String(i);
      rs.appendChild(s);
    }
  }

  function setRiskSegments(pct) {
    const n = Math.min(10, Math.max(0, Math.ceil(pct / 10)));
    el("riskPct").textContent = Math.round(pct) + "%";
    el("riskSegments").querySelectorAll("span").forEach((seg, i) => {
      seg.style.background = i < n
        ? i < 3 ? "#00c8ff" : i < 6 ? "#ffe040" : i < 9 ? "#ff6600" : "#ff2020"
        : "rgba(255,255,255,0.08)";
    });
  }

  function formatClock() {
    const d = new Date();
    el("clock").textContent = d.toLocaleTimeString("en-GB", { hour12: false });
  }

  function renderMetrics(m) {
    const keys = [
      ["txns", "TXNS"],
      ["suspects", "SUSPECTS"],
      ["mules", "MULES"],
      ["clusters", "CLUSTERS"],
      ["amount", "AMOUNT $M"],
      ["alerts", "ALERTS"],
    ];
    const grid = el("metricGrid");
    grid.innerHTML = "";
    keys.forEach(([k, label]) => {
      const card = document.createElement("div");
      card.className = "metric-card";
      const v = m[k];
      const val = k === "amount" && typeof v === "number"
        ? v.toFixed(2) + "M"
        : (v != null ? String(v) : "—");
      card.innerHTML = '<div class="ml">' + label + '</div><div class="mv" data-k="' + k + '">' + val + "</div>";
      if (k === "alerts" && (m.alerts || 0) > 6) card.classList.add("alert");
      else if (k === "suspects" && (m.suspects || 0) > 15) card.classList.add("warn");
      grid.appendChild(card);
    });
    const risk = m.risk != null ? m.risk : 0;
    setThreatLevel(risk);
    setRiskSegments(risk);
  }

  function renderBadges() {
    const g = el("graphBadges");
    const nc = state.nodes.length;
    const ec = state.edges.length;
    const hc = Object.keys(state.hulls).length;
    const ph = "LIVE";
    g.innerHTML = [
      "NODES <strong>" + nc + "</strong>",
      "EDGES <strong>" + ec + "</strong>",
      "CLUST <strong>" + hc + "</strong>",
      "PHASE <strong>" + ph + "</strong>",
    ]
      .map(
        (t) =>
          '<div class="badge">' + t + "</div>"
      )
      .join("");
  }

  function addIntel(ev) {
    const intel = ev.intel || ev;
    const feed = el("intelFeed");
    const row = document.createElement("div");
    row.className = "intel-entry";
    const lvl = intel.level || "warn";
    const c =
      lvl === "crit"
        ? "#ff3c00"
        : lvl === "success"
          ? "#00ff88"
          : "#ffe040";
    row.style.setProperty("--intel-c", c);
    const ts = new Date().toLocaleTimeString("en-GB", { hour12: false });
    row.innerHTML =
      '<div class="intel-meta">[' +
      String(lvl).toUpperCase() +
      "]  " +
      ts +
      '</div><div class="intel-body">' +
      (intel.text || "") +
      '</div><div class="intel-ctx">' +
      (intel.context || "") +
      "</div>";
    feed.appendChild(row);
  }

  function renderAttackCard(a) {
    const reg = el("attackRegistry");
    const div = document.createElement("div");
    div.className = "attack-card";
    const col = a.color || ATTACK_TYPES[a.type] || "#00c8ff";
    div.style.setProperty("--card-c", col);
    const phase = a.phase || 6;
    const pt = a.phase_total || 6;
    let dots = "";
    for (let i = 1; i <= pt; i++) {
      dots += '<span class="' + (i <= phase ? "on" : "") + '"></span>';
    }
    div.innerHTML =
      '<div class="attack-card-head"><span class="attack-id">' +
      a.id +
      '</span><span class="sev">●CRIT</span></div>' +
      '<p class="attack-title">' +
      (a.display_name || a.type) +
      "</p><hr/>" +
      '<div class="stat-row"><span>NODES ' +
      (a.node_count || 0) +
      '</span><span>EDGES ' +
      (a.edge_count || 0) +
      "</span></div>" +
      '<div class="amt-row">AMOUNT $' +
      (a.total_amount || 0).toLocaleString() +
      '</div><div class="conf-track"><div class="conf-fill" style="width:' +
      (a.confidence || 90) +
      '%"></div></div>' +
      '<div class="phase-dots">' +
      dots +
      '</div><div class="ts">' +
      (a.confirmed_at || "") +
      " CONFIRMED</div>";
    reg.insertBefore(div, reg.firstChild);
    el("atkActive").textContent = String(state.attacks.length);
  }

  function pulseCounter() {
    const n = el("acNum");
    n.classList.remove("pulse");
    void n.offsetWidth;
    n.classList.add("pulse");
  }

  function mergeNode(upd) {
    const i = state.nodes.findIndex((n) => n.id === upd.id);
    if (i >= 0) {
      const prev = state.nodes[i];
      const merged = { ...prev, ...upd };
      if (upd.attack_types && upd.attack_types.length) {
        merged.attack_types = Array.from(
          new Set([...(prev.attack_types || []), ...upd.attack_types])
        );
      }
      state.nodes[i] = merged;
    } else {
      const w = state.width || 800;
      const h = state.height || 600;
      upd.x = w / 2 + (Math.random() - 0.5) * 200;
      upd.y = h / 2 + (Math.random() - 0.5) * 200;
      state.nodes.push(upd);
    }
  }

  function mergeEdge(upd) {
    const e = { ...upd, source: upd.source_id, target: upd.target_id };
    const i = state.edges.findIndex((x) => x.id === e.id);
    if (i >= 0) state.edges[i] = { ...state.edges[i], ...e };
    else state.edges.push(e);
  }

  function buildGraphFromSnapshot(snap) {
    const wrap = document.querySelector(".graph-wrap");
    const w = wrap ? wrap.clientWidth : 800;
    const h = wrap ? wrap.clientHeight : 600;
    state.nodes = (snap.nodes || []).map(function (n, i) {
      const o = { ...n };
      o.x = w / 2 + Math.cos(i * 0.7) * 140 + Math.random() * 30;
      o.y = h / 2 + Math.sin(i * 0.7) * 140 + Math.random() * 30;
      return o;
    });
    state.edges = (snap.edges || []).map((e) => ({
      ...e,
      source: e.source_id,
      target: e.target_id,
    }));
    if (snap.metrics) {
      state.metrics = snap.metrics;
      renderMetrics(state.metrics);
    }
  }

  function updateHullForAttack(attack) {
    const ids = new Set(attack.nodes_involved || []);
    const pts = state.nodes
      .filter((n) => ids.has(n.id))
      .map((n) => [n.x, n.y]);
    if (pts.length < 3) return;
    let hull = d3.polygonHull(pts);
    if (!hull) return;
    const centroid = d3.polygonCentroid(hull);
    hull = hull.map(function (pt) {
      const dx = pt[0] - centroid[0];
      const dy = pt[1] - centroid[1];
      const len = Math.sqrt(dx * dx + dy * dy) || 1;
      return [pt[0] + (dx / len) * 30, pt[1] + (dy / len) * 30];
    });
    state.hulls[attack.id] = { hull, color: attack.color || "#00c8ff", label: attack.display_name };
  }

  function hullPath(hull) {
    return (
      "M" +
      hull
        .map(function (p, i) {
          return (i ? "L" : "") + p[0] + "," + p[1];
        })
        .join("") +
      "Z"
    );
  }

  function tickBound() {
    const w = state.width;
    const h = state.height;
    state.nodes.forEach(function (n) {
      const r = nodeRadius(n) + 10;
      n.x = Math.max(r, Math.min(w - r, n.x));
      n.y = Math.max(r, Math.min(h - r, n.y));
    });
  }

  function initSimulation() {
    const svg = d3.select("#graphSvg");
    state.svg = svg;
    const wrap = document.querySelector(".graph-wrap");
    state.width = Math.max(320, wrap.clientWidth);
    state.height = Math.max(240, wrap.clientHeight - 4);

    if (!state.nodes.length) {
      svg.attr("width", state.width).attr("height", state.height);
      svg.append("text")
        .attr("x", state.width / 2)
        .attr("y", state.height / 2)
        .attr("text-anchor", "middle")
        .attr("fill", "rgba(0,200,255,0.5)")
        .attr("font-family", "Space Mono, monospace")
        .attr("font-size", "12px")
        .text("Awaiting graph data…");
      return;
    }

    svg.attr("width", state.width).attr("height", state.height);
    svg.selectAll("*").remove();

    const defs = svg.append("defs");
    ["cyan", "red", "white"].forEach(function (name, i) {
      const blur = name === "red" ? 5 : name === "white" ? 4 : 3;
      const f = defs
        .append("filter")
        .attr("id", "glow-" + name)
        .attr("x", "-50%")
        .attr("y", "-50%")
        .attr("width", "200%")
        .attr("height", "200%");
      f.append("feGaussianBlur").attr("stdDeviation", blur).attr("result", "blur");
      const m = f.append("feMerge");
      m.append("feMergeNode").attr("in", "blur");
      m.append("feMergeNode").attr("in", "SourceGraphic");
    });

    state.hullG = svg.append("g").attr("class", "hulls");
    const gLinks = svg.append("g").attr("class", "links");
    const gNodes = svg.append("g").attr("class", "nodes");
    state.pulseLayer = svg.append("g").attr("class", "pulses");

    const sim = d3
      .forceSimulation(state.nodes)
      .force(
        "link",
        d3
          .forceLink(state.edges)
          .id(function (d) {
            return d.id;
          })
          .distance(function (d) {
            const t = d.type || "";
            if (t === "layering") return 160;
            if (t === "smurfing") return 80;
            return 120;
          })
          .strength(0.6)
      )
      .force("charge", d3.forceManyBody().strength(function (d) {
        return d.role === "hub" ? -600 : -280;
      }))
      .force("center", d3.forceCenter(state.width / 2, state.height / 2))
      .force(
        "collide",
        d3.forceCollide().radius(function (d) {
          return nodeRadius(d) + 18;
        })
      )
      .alphaDecay(0.02)
      .velocityDecay(0.4);

    sim.on("tick", function () {
      tickBound();
      if (!state.linkSel || !state.nodeSel) return;
      state.linkSel
        .attr("x1", function (d) {
          return d.source.x;
        })
        .attr("y1", function (d) {
          return d.source.y;
        })
        .attr("x2", function (d) {
          return d.target.x;
        })
        .attr("y2", function (d) {
          return d.target.y;
        });
      state.nodeSel.attr("transform", function (d) {
        return "translate(" + d.x + "," + d.y + ")";
      });
    });

    state.simulation = sim;

    state.linkSel = gLinks
      .selectAll("line")
      .data(state.edges, function (d) {
        return d.id;
      })
      .join("line")
      .attr("stroke", function (d) {
        if (d.state === "mule") return "rgba(255,32,32,0.75)";
        if (d.state === "suspicious") return "rgba(255,160,32,0.5)";
        return "rgba(0,200,255,0.12)";
      })
      .attr("stroke-width", function (d) {
        if (d.state === "mule") return 2.5;
        if (d.state === "suspicious") return 1.5;
        return 1;
      })
      .attr("stroke-dasharray", function (d) {
        return d.state === "flagged" ? "6,3" : "none";
      });

    state.nodeSel = gNodes
      .selectAll("g.node")
      .data(state.nodes, function (d) {
        return d.id;
      })
      .join(function (enter) {
        const g = enter.append("g").attr("class", "node");
        g.append("circle")
          .attr("r", nodeRadius)
          .attr("fill", function (d) {
            return d.state === "mule" ? "#1e0000" : "#0d1e30";
          })
          .attr("stroke", function (d) {
            return STATE_STROKE[d.state] || STATE_STROKE.clean;
          })
          .attr("stroke-width", 2);
        return g;
      });

    state.nodeSel.style("cursor", "grab");

    state.nodeSel.on("mousemove", function (event, d) {
      const tt = el("nodeTooltip");
      tt.hidden = false;
      tt.style.left = event.clientX + 14 + "px";
      tt.style.top = event.clientY + 14 + "px";
      tt.innerHTML =
        '<div style="font-family:Syne,sans-serif;font-weight:700;font-size:14px;color:' +
        (STATE_STROKE[d.state] || "#00c8ff") +
        '">' +
        d.id +
        "</div><hr style=\"border:0;border-top:1px solid rgba(255,255,255,0.1)\"/>" +
        '<div style="font-family:Space Mono,monospace;font-size:10px">STATE ' +
        (d.state || "") +
        "<br/>TXNS " +
        (d.txns || 0) +
        "<br/>SCORE " +
        (d.score || 0) +
        "%</div>";
    });

    state.nodeSel.on("mouseleave", function () {
      el("nodeTooltip").hidden = true;
    });

    renderBadges();
  }

  function refreshGraphData() {
    if (!state.simulation) return;
    state.edges.forEach(function (e) {
      if (e && typeof e.source === "object" && e.source) e.source = e.source.id;
      if (e && typeof e.target === "object" && e.target) e.target = e.target.id;
    });
    state.simulation.nodes(state.nodes);
    const linkForce = state.simulation.force("link");
    linkForce.links(state.edges);
    state.linkSel = d3
      .select("#graphSvg g.links")
      .selectAll("line")
      .data(state.edges, function (d) {
        return d.id;
      })
      .join("line")
      .attr("stroke", function (d) {
        if (d.state === "mule") return "rgba(255,32,32,0.75)";
        if (d.state === "suspicious") return "rgba(255,160,32,0.5)";
        return "rgba(0,200,255,0.12)";
      })
      .attr("stroke-width", function (d) {
        if (d.state === "mule") return 2.5;
        return 1.2;
      });

    state.nodeSel = d3
      .select("#graphSvg g.nodes")
      .selectAll("g.node")
      .data(state.nodes, function (d) {
        return d.id;
      })
      .join(function (enter) {
        const g = enter.append("g").attr("class", "node");
        g.append("circle")
          .attr("r", nodeRadius)
          .attr("fill", function (d) {
            return d.state === "mule" ? "#1e0000" : "#0d1e30";
          })
          .attr("stroke", function (d) {
            return STATE_STROKE[d.state] || STATE_STROKE.clean;
          })
          .attr("stroke-width", 2);
        return g;
      });

    state.nodeSel.on("mousemove", function (event, d) {
      const tt = el("nodeTooltip");
      tt.hidden = false;
      tt.style.left = event.clientX + 14 + "px";
      tt.style.top = event.clientY + 14 + "px";
      tt.innerHTML =
        '<div style="font-family:Syne,sans-serif;font-weight:700;font-size:14px">' +
        d.id +
        "</div><hr style=\"border:0;border-top:1px solid rgba(255,255,255,0.1)\"/>" +
        '<div style="font-family:Space Mono,monospace;font-size:10px">STATE ' +
        (d.state || "") +
        "<br/>TXNS " +
        (d.txns || 0) +
        "</div>";
    });
    state.nodeSel.on("mouseleave", function () {
      el("nodeTooltip").hidden = true;
    });

    state.simulation.alpha(0.4).restart();
    renderBadges();
    applyFilter();
  }

  function redrawHulls() {
    if (!state.hullG) return;
    const data = Object.entries(state.hulls);
    state.hullG
      .selectAll("path")
      .data(data)
      .join("path")
      .attr("d", function (d) {
        return hullPath(d[1].hull);
      })
      .attr("fill", function (d) {
        const c = d[1].color || "#00c8ff";
        return c.length === 7 ? c + "14" : c;
      })
      .attr("stroke", function (d) {
        const c = d[1].color || "#00c8ff";
        return c.length === 7 ? c + "99" : c;
      })
      .attr("stroke-width", 1.5)
      .attr("stroke-dasharray", "8 4");

    state.hullG
      .selectAll("text")
      .data(data)
      .join("text")
      .attr("x", function (d) {
        return d3.polygonCentroid(d[1].hull)[0];
      })
      .attr("y", function (d) {
        return d3.polygonCentroid(d[1].hull)[1];
      })
      .attr("text-anchor", "middle")
      .attr("fill", function (d) {
        return d[1].color;
      })
      .style("font-family", "Space Mono, monospace")
      .style("font-size", "9px")
      .text(function (d) {
        return d[0] + " // " + (d[1].label || "");
      });
  }

  function applyFilter() {
    const f = state.activeFilter;
    state.nodeSel.select("circle").each(function (d) {
      const sel = d3.select(this);
      if (f === "all") {
        sel.classed("node-dim", false);
        return;
      }
      const types = d.attack_types || [];
      const match = types.indexOf(f) >= 0;
      sel.classed("node-dim", !match);
    });
  }

  function renderFilters() {
    const bar = el("filterBar");
    const counts = {};
    state.attacks.forEach(function (a) {
      const t = a.type;
      counts[t] = (counts[t] || 0) + 1;
    });
    const total = state.nodes.length;
    let html =
      '<span class="filter-label">FILTER:</span>' +
      '<button type="button" class="filter-pill' +
      (state.activeFilter === "all" ? " active" : "") +
      '" data-f="all" style="--pill-c:#00c8ff">ALL ×' +
      total +
      "</button>";
    Object.keys(ATTACK_TYPES).forEach(function (t) {
      const c = counts[t] || 0;
      if (c === 0) return;
      html +=
        '<button type="button" class="filter-pill' +
        (state.activeFilter === t ? " active" : "") +
        '" data-f="' +
        t +
        '" style="--pill-c:' +
        ATTACK_TYPES[t] +
        '">' +
        t.toUpperCase().replace(/-/g, "-") +
        " ×" +
        c +
        "</button>";
    });
    bar.innerHTML = html;
    bar.querySelectorAll(".filter-pill").forEach(function (btn) {
      btn.addEventListener("click", function () {
        state.activeFilter = btn.getAttribute("data-f");
        renderFilters();
        applyFilter();
      });
    });
  }

  function showAlertBanner(alert) {
    const b = el("alertBanner");
    const col = alert.color || "#00c8ff";
    b.style.background = "rgba(" + hexToRgb(col) + ",0.08)";
    b.style.borderBottomColor = col;
    el("alertText").textContent =
      (alert.title || "") + " — " + (alert.message || "");
    el("alertText").style.color = col;
    b.querySelector(".alert-blink").style.background = col;
    b.classList.add("open");
    b.setAttribute("aria-hidden", "false");
    setTimeout(function () {
      b.classList.remove("open");
      b.setAttribute("aria-hidden", "true");
    }, 5200);
  }

  function hexToRgb(hex) {
    const h = hex.replace("#", "");
    const n = parseInt(h, 16);
    return ((n >> 16) & 255) + "," + ((n >> 8) & 255) + "," + (n & 255);
  }

  function onSnapshot(ev) {
    buildGraphFromSnapshot(ev);
    initSimulation();
  }

  function setupWS() {
    const sw = new SentinelWS(wsUrl());
    sw.on("snapshot", function (ev) {
      buildGraphFromSnapshot(ev);
      if (!state.simulation) initSimulation();
      else refreshGraphData();
      redrawHulls();
    });
    sw.on("node_update", function (ev) {
      mergeNode(ev.node);
      refreshGraphData();
    });
    sw.on("edge_update", function (ev) {
      mergeEdge(ev.edge);
      refreshGraphData();
    });
    sw.on("ml_reasoning", addIntel);
    sw.on("attack_identified", function (ev) {
      const a = ev.attack;
      state.attacks.push(a);
      state.attacksIdentified = state.attacks.length;
      el("acNum").textContent = String(Math.min(10, state.attacksIdentified));
      pulseCounter();
      renderAttackCard(a);
      (a.nodes_involved || []).forEach(function (nid) {
        const n = state.nodes.find(function (x) {
          return x.id === nid;
        });
        if (n) {
          n.attack_types = Array.from(
            new Set([...(n.attack_types || []), a.type])
          );
        }
      });
      setTimeout(function () {
        updateHullForAttack(a);
        redrawHulls();
      }, 400);
      renderFilters();
    });
    sw.on("metric_update", function (ev) {
      const d = ev.delta || {};
      state.metrics = { ...state.metrics, ...d };
      renderMetrics(state.metrics);
    });
    sw.on("alert", function (ev) {
      showAlertBanner(ev.alert || ev);
    });
    sw.on("simulation_complete", function () {
      el("completionBanner").classList.remove("hidden");
      el("filterBar").classList.add("hidden");
      el("btnExport").classList.remove("hidden");
      el("intelFeed").parentElement.classList.add("hidden");
      el("sarCard").classList.remove("hidden");
      el("sarCard").innerHTML =
        "<h4>SUSPICIOUS ACTIVITY REPORT</h4><p>AUTO-GENERATED SUMMARY</p><hr/>" +
        "<p>TOTAL ATTACKS: 10<br/>NODES FLAGGED: " +
        state.nodes.length +
        "</p>" +
        '<p style="margin-top:8px"><button type="button" onclick="alert(\'Export stub\')">EXPORT JSON</button></p>';
    });
  }

  function triggerAttack() {
    const idx = state.attackIndex;
    state.attackIndex = (state.attackIndex + 1) % 10;
    fetch("/trigger_attack?index=" + idx).catch(function () {});
  }

  function resetSim() {
    fetch("/reset_state").catch(function () {});
    state.attacks = [];
    state.hulls = {};
    state.attackIndex = 0;
    el("acNum").textContent = "0";
    el("attackRegistry").innerHTML = "";
    el("completionBanner").classList.add("hidden");
    el("filterBar").classList.remove("hidden");
    el("btnExport").classList.add("hidden");
    el("intelFeed").parentElement.classList.remove("hidden");
    el("sarCard").classList.add("hidden");
  }

  function init() {
    el("sessionId").textContent =
      "SESSION " + Math.random().toString(16).slice(2, 10).toUpperCase();
    initThreatBar();
    initRiskSegments();
    formatClock();
    setInterval(formatClock, 1000);
    setupWS();
    el("btnTrigger").addEventListener("click", triggerAttack);
    el("btnReset").addEventListener("click", resetSim);
    el("alertDismiss").addEventListener("click", function () {
      el("alertBanner").classList.remove("open");
    });
    window.addEventListener("resize", function () {
      if (state.simulation) {
        const wrap = document.querySelector(".graph-wrap");
        state.width = wrap.clientWidth;
        state.height = wrap.clientHeight;
        d3.select("#graphSvg").attr("width", state.width).attr("height", state.height);
        state.simulation.force("center", d3.forceCenter(state.width / 2, state.height / 2));
        state.simulation.alpha(0.3).restart();
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
