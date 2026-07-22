/* ============================================================
   SELENE — shared runtime
   Particle network, scroll reveal, counters, tilt, ticker,
   page transitions, modal + toast helpers.
   Pure vanilla JS, no dependencies.
   ============================================================ */

/* ---------- Particle constellation background ---------- */
(function particles() {
  const c = document.getElementById("particles");
  if (!c) return;
  const ctx = c.getContext("2d");
  let W, H, pts = [];
  const N = Math.min(90, Math.floor(window.innerWidth / 16));
  const mouse = { x: -9999, y: -9999 };

  function resize() { W = c.width = window.innerWidth; H = c.height = window.innerHeight; }
  window.addEventListener("resize", resize);
  resize();

  for (let i = 0; i < N; i++) {
    pts.push({
      x: Math.random() * W, y: Math.random() * H,
      vx: (Math.random() - .5) * .35, vy: (Math.random() - .5) * .35,
      r: Math.random() * 1.6 + .6,
      hue: Math.random() < .5 ? "34,211,238" : "167,139,250",
    });
  }

  window.addEventListener("mousemove", e => { mouse.x = e.clientX; mouse.y = e.clientY; });
  window.addEventListener("mouseleave", () => { mouse.x = -9999; mouse.y = -9999; });

  function tick() {
    ctx.clearRect(0, 0, W, H);
    for (const p of pts) {
      const dx = p.x - mouse.x, dy = p.y - mouse.y;
      const d2 = dx * dx + dy * dy;
      if (d2 < 16000) { p.vx += dx / d2 * 9; p.vy += dy / d2 * 9; }
      p.vx = Math.max(-.7, Math.min(.7, p.vx));
      p.vy = Math.max(-.7, Math.min(.7, p.vy));
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${p.hue},.65)`; ctx.fill();
    }
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        const a = pts[i], b = pts[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const d = dx * dx + dy * dy;
        if (d < 13000) {
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = `rgba(120,140,255,${.14 * (1 - d / 13000)})`;
          ctx.lineWidth = 1; ctx.stroke();
        }
      }
    }
    requestAnimationFrame(tick);
  }
  tick();
})();

/* ---------- Scroll reveal ---------- */
(function reveal() {
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
  }, { threshold: .12 });
  document.querySelectorAll(".reveal").forEach(el => io.observe(el));
})();

/* ---------- Animated counters ---------- */
(function counters() {
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      const el = e.target; io.unobserve(el);
      const target = parseFloat(el.dataset.count);
      const decimals = (el.dataset.count.split(".")[1] || "").length;
      const suffix = el.dataset.suffix || "";
      const dur = 1800, t0 = performance.now();
      (function step(t) {
        const k = Math.min(1, (t - t0) / dur);
        const eased = 1 - Math.pow(1 - k, 4);
        el.textContent = (target * eased).toFixed(decimals) + suffix;
        if (k < 1) requestAnimationFrame(step);
      })(t0);
    });
  }, { threshold: .4 });
  document.querySelectorAll("[data-count]").forEach(el => io.observe(el));
})();

/* ---------- Card cursor glow ---------- */
document.addEventListener("mousemove", e => {
  document.querySelectorAll(".card").forEach(card => {
    const r = card.getBoundingClientRect();
    card.style.setProperty("--mx", (e.clientX - r.left) + "px");
    card.style.setProperty("--my", (e.clientY - r.top) + "px");
  });
});

/* ---------- 3D tilt ---------- */
document.querySelectorAll(".tilt").forEach(el => {
  el.addEventListener("mousemove", e => {
    const r = el.getBoundingClientRect();
    const rx = ((e.clientY - r.top) / r.height - .5) * -8;
    const ry = ((e.clientX - r.left) / r.width - .5) * 8;
    el.style.transform = `perspective(800px) rotateX(${rx}deg) rotateY(${ry}deg) translateY(-6px)`;
  });
  el.addEventListener("mouseleave", () => { el.style.transform = ""; });
});

/* ---------- Threat intel ticker ---------- */
(function ticker() {
  const host = document.getElementById("ticker");
  if (!host) return;
  const items = [
    ["T1110.001", "Brute Force: Password Guessing — 100% detection"],
    ["CVE-2026-21412", "OpenSSH auth bypass — auto-indexed (score 9)"],
    ["T1059.004", "Unix Shell execution — ensemble CRITICAL"],
    ["SIGMA", "3,005 detection rules indexed"],
    ["CISA KEV", "actively exploited catalog synced 02:00"],
    ["T1078", "Valid Accounts — behavioral baseline active"],
    ["ENSEMBLE", "IF + Autoencoder · F1 89.2%"],
    ["RAG", "hybrid dense + BM25 · RRF fusion · k=5"],
    ["T1571", "Non-Standard Port C2 beacon — blocked"],
    ["MITRE", "823 ATT&CK techniques in knowledge base"],
  ];
  const html = items.map(([tag, txt]) => `<span><b>[${tag}]</b> ${txt}</span>`).join("");
  host.innerHTML = html + html;
})();

/* ---------- Fill score bars when visible ---------- */
(function bars() {
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      const fill = e.target.querySelector("i");
      if (fill) fill.style.width = (e.target.dataset.fill || 0) + "%";
      io.unobserve(e.target);
    });
  }, { threshold: .5 });
  document.querySelectorAll(".bar[data-fill]").forEach(el => io.observe(el));
})();

/* ---------- Shared helpers ---------- */
window.NX = {
  type(el, text, speed = 14) {
    return new Promise(res => {
      let i = 0; el.classList.add("cursor");
      (function step() {
        el.innerHTML = text.slice(0, ++i).replace(/\n/g, "<br>");
        if (i < text.length) setTimeout(step, speed);
        else { el.classList.remove("cursor"); res(); }
      })();
    });
  },
  rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; },
  pad(n) { return String(n).padStart(2, "0"); },
  now() { const d = new Date(); return `${this.pad(d.getHours())}:${this.pad(d.getMinutes())}:${this.pad(d.getSeconds())}`; },
  openModal(id) { const m = document.getElementById(id); if (m) { m.classList.add("open"); document.body.style.overflow = "hidden"; } },
  closeModal(id) { const m = document.getElementById(id); if (m) { m.classList.remove("open"); document.body.style.overflow = ""; } },
  toast(msg, ms = 2600) {
    let t = document.querySelector(".toast");
    if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.appendChild(t); }
    t.textContent = msg;
    requestAnimationFrame(() => t.classList.add("show"));
    clearTimeout(t._h);
    t._h = setTimeout(() => t.classList.remove("show"), ms);
  },
  /* animate a stat element to a live value — from the CURRENTLY displayed
     value, not from 0, so refreshes nudge instead of re-growing every time */
  count(el, target, suffix = "", decimals = 0) {
    if (!el) return;
    const start = parseFloat(el.textContent) || 0;
    if (start === target) { el.textContent = target.toFixed(decimals) + suffix; return; }
    const dur = 700, t0 = performance.now();
    (function step(t) {
      const k = Math.min(1, (t - t0) / dur);
      const eased = 1 - Math.pow(1 - k, 4);
      el.textContent = (start + (target - start) * eased).toFixed(decimals) + suffix;
      if (k < 1) requestAnimationFrame(step);
    })(t0);
  },
};

/* ---------- Page transitions ---------- */
document.querySelectorAll(".nav a.link, a.brand, a[data-nav]").forEach(a => {
  a.addEventListener("click", e => {
    const href = a.getAttribute("href");
    if (!href || href.startsWith("#") || a.target === "_blank") return;
    e.preventDefault();
    document.body.classList.add("page-leave");
    setTimeout(() => { location.href = href; }, 240);
  });
});

/* ---------- Inject the ML Engine nav link on every page ---------- */
(function injectMlLink() {
  const nav = document.querySelector(".nav");
  if (!nav) return;
  // already present (e.g. on ml.html itself)?
  if ([...nav.querySelectorAll("a.link")].some(a => (a.getAttribute("href") || "").includes("ml.html"))) return;
  const alertsLink = [...nav.querySelectorAll("a.link")].find(a => (a.getAttribute("href") || "").includes("alerts.html"));
  const link = document.createElement("a");
  link.className = "link"; link.href = "ml.html"; link.textContent = "ML Engine";
  if (location.pathname.endsWith("ml.html")) link.classList.add("active");
  if (alertsLink && alertsLink.nextSibling) nav.insertBefore(link, alertsLink.nextSibling);
  else if (alertsLink) alertsLink.after(link);
  // bind page-transition on the injected link
  link.addEventListener("click", e => {
    e.preventDefault();
    document.body.classList.add("page-leave");
    setTimeout(() => { location.href = "ml.html"; }, 240);
  });
})();

/* ---------- Nav shrink on scroll ---------- */
(function navShrink() {
  const nav = document.querySelector(".nav");
  if (!nav) return;
  window.addEventListener("scroll", () => {
    const y = window.scrollY;
    if (y > 90) nav.classList.add("shrunk");
    else if (y < 40) nav.classList.remove("shrunk");
  }, { passive: true });
})();

/* ---------- Close modals on overlay click / Esc ---------- */
document.querySelectorAll(".modal-overlay").forEach(ov => {
  ov.addEventListener("click", e => { if (e.target === ov) NX.closeModal(ov.id); });
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape") document.querySelectorAll(".modal-overlay.open").forEach(m => NX.closeModal(m.id));
});

/* ============================================================
   SELENE — global list managers in the nav/tab bar
   One reusable factory drives BOTH the Suspicious Groups and the
   Benign Rules managers. Each lives in the constant nav bar on
   every page and persists to the REAL backend:
     benign     → GET/POST /api/benign-rules, DELETE /api/benign-rules/<id>
     suspicious → GET/POST /api/suspicious-groups, DELETE /api/suspicious-groups/<name>
   plus the curated suggestion lists (suggested-* endpoints).
   ============================================================ */
function makeNavManager(cfg) {
  const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  let items = [];       // [{name, desc}] mirrored from the backend
  let suggested = [];   // curated suggestions not yet active

  const norm = row => ({ name: String(row[cfg.fldName]), desc: row[cfg.fldDesc] || "" });
  const notify = () => window.dispatchEvent(new CustomEvent(cfg.evt));

  async function refresh() {
    try {
      const r = await fetch(cfg.endpoint);
      const data = await r.json();
      items = (data[cfg.listKey] || []).map(norm);
    } catch (e) { console.error(cfg.short, "load failed:", e); }
    try {
      const r = await fetch(cfg.suggestedEndpoint);
      const data = await r.json();
      const active = new Set(items.map(x => x.name));
      suggested = (data[cfg.listKey] || []).map(norm).filter(s => !active.has(s.name));
    } catch (e) { suggested = []; }
    notify();
  }

  const api = {
    list() { return items.slice(); },
    suggested() { return suggested.slice(); },
    has(name) { return items.some(x => x.name === String(name)); },
    async add(name, desc) {
      name = String(name || "").trim();
      if (!name || api.has(name)) return false;
      const body = {}; body[cfg.fldName] = name; body[cfg.fldDesc] = desc || cfg.defDesc;
      const r = await fetch(cfg.endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) return false;
      await refresh(); return true;
    },
    async remove(name) {
      const r = await fetch(cfg.endpoint + "/" + encodeURIComponent(name), { method: "DELETE" });
      if (!r.ok) return false;
      await refresh(); return true;
    },
    async update(oldName, name, desc) {   // backend has no PUT — replace = delete + add
      name = String(name || "").trim();
      if (!name) return false;
      await api.remove(oldName);
      return api.add(name, desc);
    },
  };
  if (!window.NX) window.NX = {};
  NX[cfg.api] = api;

  let modal, editing = null;
  function injectNavButton() {
    const nav = document.querySelector(".nav");
    if (!nav || nav.querySelector("." + cfg.btnClass)) return;
    const btn = document.createElement("button");
    btn.type = "button"; btn.className = "nav-mgr-btn " + cfg.btnClass;
    btn.innerHTML = `${cfg.icon} ${cfg.short} <span class="nav-mgr-count">0</span>`;
    btn.addEventListener("click", openModal);
    const pill = nav.querySelector(".status-pill");
    if (pill) nav.insertBefore(btn, pill); else nav.appendChild(btn);
    window.addEventListener(cfg.evt, () => { const c = btn.querySelector(".nav-mgr-count"); if (c) c.textContent = items.length; });
  }
  function buildModal() {
    modal = document.createElement("div");
    modal.className = "modal-overlay"; modal.id = cfg.modalId;
    modal.innerHTML = `
      <div class="modal">
        <button class="modal-close" data-close>✕</button>
        <h3>${cfg.icon} ${cfg.title}</h3>
        <div class="modal-sub">${cfg.sub}</div>
        <div style="display:flex;gap:10px;margin-bottom:16px;">
          <input class="nx-input mgr-name" placeholder="${cfg.namePh}" style="width:170px;">
          <input class="nx-input mgr-desc" placeholder="description (optional)" style="flex:1;">
          <button class="btn btn-primary mgr-add" style="padding:10px 18px;">Add</button>
        </div>
        <div class="mgr-list"></div>
        <div class="mgr-suggested"></div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener("click", e => { if (e.target === modal || e.target.hasAttribute("data-close")) close(); });
    modal.querySelector(".mgr-add").addEventListener("click", async () => {
      const n = modal.querySelector(".mgr-name"), d = modal.querySelector(".mgr-desc");
      if (await api.add(n.value, d.value)) { n.value = ""; d.value = ""; NX.toast && NX.toast(cfg.addedMsg); }
      else NX.toast && NX.toast(`Enter a new, unique ${cfg.noun}`);
    });
    window.addEventListener(cfg.evt, () => { if (modal.classList.contains("open")) render(); });
  }
  function render() {
    const list = modal.querySelector(".mgr-list");
    list.innerHTML = api.list().map(g => {
      if (editing === String(g.name)) {
        return `<div class="card" style="padding:12px 16px;display:flex;gap:8px;align-items:center;margin-bottom:8px;border-color:${cfg.edge};">
          <input class="nx-input gse-name" value="${esc(g.name)}" style="width:150px;">
          <input class="nx-input gse-desc" value="${esc(g.desc || '')}" style="flex:1;">
          <button class="btn-mini ok gse-save">Save</button>
          <button class="btn-mini view gse-cancel">Cancel</button></div>`;
      }
      return `<div class="card" style="padding:12px 16px;display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <span><b style="color:${cfg.color}">${cfg.prefix}${esc(g.name)}</b> <span style="color:var(--text-dim);font-size:12px">— ${esc(g.desc || cfg.defDesc)}</span></span>
        <span style="display:flex;gap:8px;">
          <button class="btn-mini view gse-edit" data-n="${esc(g.name)}">✎ Edit</button>
          <button class="btn-mini no gse-rm" data-n="${esc(g.name)}">Remove</button>
        </span></div>`;
    }).join("") || `<p style="color:var(--text-dim)">${cfg.empty}</p>`;
    list.querySelectorAll(".gse-edit").forEach(b => b.onclick = () => { editing = b.dataset.n; render(); });
    list.querySelectorAll(".gse-rm").forEach(b => b.onclick = async () => { await api.remove(b.dataset.n); NX.toast && NX.toast("Removed"); });
    list.querySelectorAll(".gse-cancel").forEach(b => b.onclick = () => { editing = null; render(); });
    list.querySelectorAll(".gse-save").forEach(b => b.onclick = async () => {
      const row = b.closest(".card");
      const nn = row.querySelector(".gse-name").value, dd = row.querySelector(".gse-desc").value;
      if (nn.trim()) { await api.update(editing, nn, dd); editing = null; }
      else NX.toast && NX.toast("Name required");
    });

    // curated suggestions (from the backend's suggested-* JSON) — one-click add
    const sug = modal.querySelector(".mgr-suggested");
    const sugItems = api.suggested();
    sug.innerHTML = !sugItems.length ? "" : `
      <div style="margin-top:18px;padding-top:14px;border-top:1px dashed var(--border,rgba(255,255,255,.12));">
        <div style="font-size:11px;letter-spacing:2px;color:var(--text-dim);margin-bottom:10px;">SUGGESTED (${sugItems.length})</div>
        ${sugItems.map(s => `
          <div class="card" style="padding:10px 16px;display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;opacity:.85;">
            <span><b style="color:${cfg.color}">${cfg.prefix}${esc(s.name)}</b> <span style="color:var(--text-dim);font-size:12px">— ${esc(s.desc)}</span></span>
            <button class="btn-mini ok sug-add" data-n="${esc(s.name)}" data-d="${esc(s.desc)}">+ Add</button>
          </div>`).join("")}
      </div>`;
    sug.querySelectorAll(".sug-add").forEach(b => b.onclick = async () => {
      if (await api.add(b.dataset.n, b.dataset.d)) NX.toast && NX.toast(cfg.addedMsg);
    });
  }
  function openModal() { editing = null; render(); modal.classList.add("open"); document.body.style.overflow = "hidden"; refresh(); }
  function close() { modal.classList.remove("open"); document.body.style.overflow = ""; }

  function init() { injectNavButton(); buildModal(); refresh(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
}

// Benign first (appears left), then Suspicious — both in the constant tab bar.
makeNavManager({
  evt: "benign-changed", api: "benign",
  endpoint: "/api/benign-rules", suggestedEndpoint: "/api/suggested-benign-rules",
  listKey: "rules", fldName: "rule_id", fldDesc: "rule_description",
  btnClass: "nav-benign-btn", modalId: "gBenignModal",
  icon: "🛡", short: "Benign", title: "Benign Rule Exceptions",
  sub: "rules marked benign are zero-scored and excluded from anomaly detection — instant, no retraining",
  namePh: "rule ID e.g. 5501", noun: "rule ID", addedMsg: "Rule marked benign 🛡",
  color: "var(--cyan)", edge: "rgba(34,211,238,.5)", prefix: "rule ", defDesc: "user-defined",
  empty: "No benign rules yet.",
});
makeNavManager({
  evt: "susp-changed", api: "susp",
  endpoint: "/api/suspicious-groups", suggestedEndpoint: "/api/suggested-suspicious-groups",
  listKey: "groups", fldName: "group_name", fldDesc: "description",
  btnClass: "nav-susp-btn", modalId: "gSuspModal",
  icon: "⚡", short: "Suspicious", title: "Suspicious Groups",
  sub: "tagged groups boost the anomaly score — live on the scoring engine, no retraining",
  namePh: "group name e.g. docker", noun: "group name", addedMsg: "Group added ⚡",
  color: "var(--amber)", edge: "rgba(251,191,36,.5)", prefix: "", defDesc: "user-defined",
  empty: "No suspicious groups yet.",
});

/* ---------- Auth session guard ---------- */
/* Every page except login.html: verify the session cookie; bounce to the
   login screen when missing/expired, and add a logout chip to the nav. */
(function authGuard() {
  if (location.pathname.endsWith("/login.html")) return;
  fetch("/api/auth/me").then(async (r) => {
    if (r.status === 401) { location.href = "/login.html"; return; }
    if (!r.ok) return;
    const d = await r.json();
    if (!d.auth_enabled || !d.user) return;
    const nav = document.querySelector(".nav");
    if (!nav) return;
    // Landing link closes the loop: landing → login → console → landing
    const home = document.createElement("a");
    home.className = "link";
    home.href = "landing.html";
    home.title = "Public landing page";
    home.style.cssText = "opacity:.75;";
    home.textContent = "Landing";
    nav.appendChild(home);
    const chip = document.createElement("a");
    chip.className = "link";
    chip.href = "profile.html";
    chip.title = "Your profile";
    chip.style.cssText = "opacity:.9;display:inline-flex;align-items:center;gap:6px;";
    chip.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5"/></svg>${d.user.username}`;
    nav.appendChild(chip);
    const out = document.createElement("a");
    out.className = "link";
    out.style.cssText = "cursor:pointer;opacity:.7;";
    out.title = "Sign out";
    out.setAttribute("aria-label", "Sign out");
    out.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5M21 12H9"/></svg>';
    out.addEventListener("click", async () => {
      await fetch("/api/auth/logout", { method: "POST" });
      location.href = "/landing.html";
    });
    nav.appendChild(out);
  }).catch(() => {});
})();

/* ---------- Cinematic cohesion layer (2026-07-18) ----------
   Injects the shared motion elements on every console page: scroll
   progress bar, cursor key light, and wave-staggered grid reveals.
   The landing page has its own engine and is excluded. */
(function cinematic() {
  if (location.pathname.endsWith("/landing.html")) return;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // scroll progress bar
  const prog = document.createElement("div");
  prog.className = "scroll-progress";
  prog.setAttribute("aria-hidden", "true");
  document.body.appendChild(prog);
  let ticking = false;
  addEventListener("scroll", () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const h = document.documentElement;
      const max = h.scrollHeight - innerHeight;
      prog.style.transform = "scaleX(" + (max > 0 ? Math.min(1, scrollY / max) : 0) + ")";
      ticking = false;
    });
  }, { passive: true });

  if (reduced) return;

  // cursor key light (transform-only, no repaints)
  const light = document.createElement("div");
  light.className = "key-light";
  light.setAttribute("aria-hidden", "true");
  document.body.appendChild(light);
  let mx = innerWidth / 2, my = innerHeight / 3, lx = mx, ly = my;
  addEventListener("pointermove", (e) => { mx = e.clientX; my = e.clientY; }, { passive: true });
  (function glow() {
    lx += (mx - lx) * 0.08; ly += (my - ly) * 0.08;
    light.style.transform = "translate3d(" + lx.toFixed(1) + "px," + ly.toFixed(1) + "px,0)";
    requestAnimationFrame(glow);
  })();

  // wave-staggered reveal for card grids that aren't already using .reveal
  document.querySelectorAll(".grid-2, .grid-3").forEach((grid) => {
    [...grid.children].forEach((el, i) => {
      if (el.classList.contains("reveal")) return;
      el.classList.add("stagger-in");
      el.style.setProperty("--sd", (i * 0.06).toFixed(2) + "s");
    });
  });
  const sio = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add("in"); sio.unobserve(e.target); }
    });
  }, { threshold: 0.15 });
  document.querySelectorAll(".stagger-in").forEach((el) => sio.observe(el));
})();
