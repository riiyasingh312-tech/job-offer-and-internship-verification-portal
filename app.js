// OfferCheck frontend: login, 5 verification tabs, results, history, accuracy.
// All user/server text is inserted with textContent (never innerHTML), so it can't inject HTML.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

function h(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  kids.flat().forEach(c => { if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c))); });
  return e;
}

const state = { user: null, lastResult: null };
const MODULE_LABEL = { company: "Company", offer_letter: "Offer letter", message: "Message", url: "Website", resume: "Resume" };
const VERDICT = {
  green: "No major warning signs found. Still confirm through the company's official website.",
  amber: "Some warning signs found. Verify carefully before sharing documents or money.",
  red: "Strong scam indicators. Do NOT pay money or share personal documents.",
};
const COLORS = { green: "#02c39a", amber: "#f2b134", red: "#d64550", blue: "#028090" };

/* ------------------------------------------------------------------ helpers */
async function api(path, opts = {}) {
  let res;
  try { res = await fetch(path, { credentials: "same-origin", ...opts }); }
  catch { throw new Error("Cannot reach the server. Make sure it is running (run.bat / python app.py)."); }
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && !path.startsWith("/api/auth/")) { showAuth(); throw new Error("Your session expired. Please log in again."); }
  if (!res.ok) throw Object.assign(new Error((data && data.error) || "Something went wrong"), { status: res.status });
  return data;
}
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add("hidden"), 2600);
}
const colorFor = level => /^Likely Genuine/.test(level) ? "green" : /^Suspicious/.test(level) ? "amber" : "red";
const gradeColor = g => g === "Excellent" || g === "Good" ? "green" : g === "Needs work" ? "amber" : "red";

/* ------------------------------------------------------------------ auth */
function setAuthTab(name) {
  $$("[data-auth]").forEach(x => x.classList.toggle("active", x.dataset.auth === name));
  $("#form-login").classList.toggle("hidden", name !== "login");
  $("#form-register").classList.toggle("hidden", name !== "register");
}
function showAuth() { setAuthTab("login"); state.user = null; $("#app-view").classList.add("hidden"); $("#auth-view").classList.remove("hidden"); }
function showApp(user) {
  state.user = user;
  $("#auth-view").classList.add("hidden"); $("#app-view").classList.remove("hidden");
  $("#avatar").textContent = user.name.trim()[0].toUpperCase();
  $("#user-name").textContent = user.name;
  $("#hello").textContent = `Hi ${user.name.split(" ")[0]}, what would you like to verify?`;
  loadHistory(); loadMetrics();
}

$$("[data-auth]").forEach(b => b.addEventListener("click", () => setAuthTab(b.dataset.auth)));

$("#form-register [name=password]").addEventListener("input", e => {
  const p = e.target.value;
  const level = !p ? 0 : Math.min(4, (p.length >= 8) + (/[A-Z]/.test(p) && /[a-z]/.test(p)) + /\d/.test(p) + /[^A-Za-z0-9]/.test(p));
  $("#strength").dataset.level = level;
});

async function submitAuth(form, endpoint) {
  const err = $(".form-error", form), btn = $("button[type=submit]", form);
  err.classList.add("hidden"); btn.disabled = true;
  const body = {}; new FormData(form).forEach((v, k) => { body[k] = String(v); });
  try {
    const data = await api(`/api/auth/${endpoint}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    form.reset(); showApp(data.user);
  } catch (e) { err.textContent = e.message; err.classList.remove("hidden"); }
  finally { btn.disabled = false; }
}
$("#form-login").addEventListener("submit", e => { e.preventDefault(); submitAuth(e.target, "login"); });
$("#form-register").addEventListener("submit", e => { e.preventDefault(); submitAuth(e.target, "register"); });
$("#logout").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" }).catch(() => {});
  showResult("result-empty"); showAuth();
});

/* ------------------------------------------------------------------ tabs, examples, uploads */
const TAB_PANEL = { company: "panel-company", offer: "panel-offer", message: "panel-message", url: "panel-url", resume: "panel-resume" };
$$(".tab").forEach(btn => btn.addEventListener("click", () => {
  $$(".tab").forEach(b => b.classList.toggle("active", b === btn));
  $$(".panel").forEach(p => p.classList.toggle("active", p.id === TAB_PANEL[btn.dataset.tab]));
  showResult("result-empty");
}));
$$("[data-fill]").forEach(a => a.addEventListener("click", e => {
  e.preventDefault();
  const form = a.closest("form");
  Object.entries(JSON.parse(a.dataset.fill)).forEach(([k, v]) => { form.elements[k].value = v; });
}));

$$("form[data-upload]").forEach(form => {
  form.dataset.mode = "pdf";
  const drop = $(".drop", form), input = $("input[type=file]", form), name = $(".file-name", form), original = name.textContent;
  $$(".seg", form).forEach(seg => seg.addEventListener("click", () => {
    form.dataset.mode = seg.dataset.mode;
    $$(".seg", form).forEach(s => s.classList.toggle("active", s === seg));
    drop.classList.toggle("hidden", seg.dataset.mode !== "pdf");
    $(".text-wrap", form).classList.toggle("hidden", seg.dataset.mode !== "text");
  }));
  input.addEventListener("change", () => { name.textContent = input.files[0] ? input.files[0].name : original; });
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => { if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; input.dispatchEvent(new Event("change")); } });
});

/* ------------------------------------------------------------------ submit a check */
const LOADING_TEXT = { company: "Checking company, domain age and look-alikes…", url: "Inspecting the website (live checks)…", "offer-letter": "Reading and analysing the letter…", message: "Scanning the message…", resume: "Analysing your resume…" };

$$("form.panel").forEach(form => form.addEventListener("submit", async e => {
  e.preventDefault();
  const endpoint = form.dataset.endpoint, btn = $("button[type=submit]", form);
  let options;
  if (form.hasAttribute("data-upload")) {
    if (form.dataset.mode === "pdf") {
      const f = $("input[type=file]", form).files[0];
      if (!f) return showError("Please choose a PDF file first.");
      const fd = new FormData(); fd.append("file", f);
      options = { method: "POST", body: fd };
    } else {
      const text = form.elements["text"].value.trim();
      if (!text) return showError("Please paste some text first.");
      options = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) };
    }
  } else {
    const body = {}; new FormData(form).forEach((v, k) => { body[k] = String(v).trim(); });
    options = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  }
  btn.disabled = true;
  $("#loading-text").textContent = LOADING_TEXT[endpoint] || "Analysing…";
  showResult("result-loading");
  try {
    const data = await api(`/api/verify/${endpoint}`, options);
    renderResult(data); loadHistory();
    if (innerWidth <= 900) $("#result").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) { showError(err.message); }
  finally { btn.disabled = false; }
}));

/* ------------------------------------------------------------------ result rendering */
function showResult(id) { ["result-empty", "result-loading", "result-out", "result-err"].forEach(x => $("#" + x).classList.toggle("hidden", x !== id)); }
function showError(msg) { $("#result-err").textContent = "⚠ " + msg; showResult("result-err"); }

function gauge(value, color, label) {
  const g = h("div", { class: "gauge" }, h("div", { class: "gauge-inner" }, h("b", {}, String(value)), h("small", {}, label)));
  g.style.setProperty("--col", COLORS[color]);
  requestAnimationFrame(() => requestAnimationFrame(() => g.style.setProperty("--pct", value)));
  return g;
}
function confBar(pct, label) {
  const fill = h("i");
  requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = pct + "%"; }));
  return h("div", { class: "conf", title: "How sure the system is about this verdict. Not a guarantee." }, h("span", {}, label), h("div", { class: "bar" }, fill), h("b", {}, pct + "%"));
}
function section(title, items) { return items.length ? [h("h4", {}, title), ...items] : []; }

function renderResult(r) {
  state.lastResult = r;
  const out = $("#result-out"); out.replaceChildren(); out.classList.add("fade");
  out.append(...(r.module === "resume" ? resumeView(r) : riskView(r)));
  const actions = h("div", { class: "actions" },
    h("button", { class: "btn small ghost", type: "button", onclick: copyReport }, "📋 Copy report"),
    h("button", { class: "btn small ghost", type: "button", onclick: () => print() }, "🖨 Print"));
  out.append(actions);
  if (r.history_used != null && r.history_used >= r.history_limit)
    out.append(h("p", { class: "note" }, `History is full (${r.history_limit}). Oldest checks are deleted automatically — or clear them yourself below.`));
  showResult("result-out");
}

function riskView(r) {
  const color = colorFor(r.risk_level), live = r.details && r.details.live_checked;
  const chips = [h("span", { class: "chip" }, MODULE_LABEL[r.module])];
  if (["url", "company", "message", "offer_letter"].includes(r.module))
    chips.push(h("span", { class: "chip" + (live ? "" : " off") }, live ? "🌐 Live checks done" : "Offline checks only"));
  return [
    h("div", { class: "res-head" },
      gauge(r.risk_score, color, "risk / 100"),
      h("div", { class: "res-meta" },
        h("span", { class: "badge " + color }, (color === "green" ? "🟢 " : color === "amber" ? "🟡 " : "🔴 ") + r.risk_level),
        h("p", { class: "verdict" }, VERDICT[color]),
        confBar(r.confidence, "Confidence"))),
    h("div", { class: "chips" }, chips),
    ...section("Warning signs", r.flags.map(f => h("div", { class: "flag" }, h("span", { class: "sev " + f.severity }, f.severity), h("span", {}, f.text)))),
    ...(r.flags.length ? [] : [h("p", { class: "pass" }, "No warning signs detected in the information provided.")]),
    ...section("Checks passed", r.passed.map(p => h("div", { class: "pass" }, p))),
    ...section("How to improve / stay safe", r.tips.map(t => h("div", { class: "tip" }, t))),
    h("div", { class: "next" }, h("h4", {}, "What to do next"), h("ul", { class: "list" }, r.next_steps.map(s => h("li", {}, s)))),
    h("p", { class: "note" }, "An automated estimate, not proof. When in doubt, contact the company through its official website and never pay to get a job."),
  ];
}

function resumeView(r) {
  const color = gradeColor(r.grade), groups = {};
  r.checks.forEach(c => (groups[c.group] = groups[c.group] || []).push(c));
  const st = r.stats;
  return [
    h("div", { class: "res-head" },
      gauge(r.resume_score, color, "ATS score"),
      h("div", { class: "res-meta" },
        h("span", { class: "badge " + color }, r.grade),
        h("p", { class: "verdict" }, `ATS readiness: ${r.ats_readiness}%. ${r.resume_score >= 70 ? "Recruiters and screening software should read this well." : "A few fixes below will raise your score quickly."}`),
        confBar(r.confidence, "Analysis confidence"))),
    h("div", { class: "chips" },
      h("span", { class: "chip" }, `${st.words} words`), h("span", { class: "chip" }, `${st.action_verbs} action verbs`),
      h("span", { class: "chip" }, `${st.measurable_results} measurable results`), h("span", { class: "chip" }, `${st.bullets} bullets`)),
    ...section("Improve these first", r.tips.map(t => h("div", { class: "tip" }, t))),
    ...section("Red flags", r.red_flags.map(t => h("div", { class: "flag" }, h("span", { class: "sev high" }, "fix"), h("span", {}, t)))),
    ...Object.entries(groups).flatMap(([g, items]) => section(g, items.map(c =>
      h("div", { class: "check-row " + (c.ok ? "ok" : "no") }, h("span", { class: "mark" }, c.ok ? "✓" : "✗"), h("span", {}, c.name), h("span", { class: "pts" }, `${c.earned}/${c.points}`))))),
  ];
}

function copyReport() {
  const r = state.lastResult; if (!r) return;
  const lines = r.module === "resume"
    ? [`OfferCheck resume report`, `Score: ${r.resume_score}/100 (${r.grade})`, "", "Improve:", ...r.tips.map(t => "- " + t), "", "Red flags:", ...r.red_flags.map(t => "- " + t)]
    : [`OfferCheck report (${MODULE_LABEL[r.module]})`, `Risk: ${r.risk_score}/100 - ${r.risk_level} (confidence ${r.confidence}%)`, "", "Warning signs:", ...r.flags.map(f => `- [${f.severity}] ${f.text}`), "", "Next steps:", ...r.next_steps.map(s => "- " + s)];
  navigator.clipboard.writeText(lines.join("\n")).then(() => toast("Report copied"), () => toast("Could not copy"));
}

/* ------------------------------------------------------------------ history */
let historyTimer;
async function loadHistory() {
  const module = $("#history-filter").value, q = $("#history-search").value.trim();
  try {
    const data = await api(`/api/history?module=${encodeURIComponent(module)}&q=${encodeURIComponent(q)}`);
    const body = $("#history-body"); body.replaceChildren();
    if (!data.items.length) body.append(h("tr", {}, h("td", { colspan: 7, class: "muted" }, q || module ? "No matching checks." : "No checks yet.")));
    data.items.forEach(it => {
      const color = it.module === "resume" ? "blue" : colorFor(it.level);
      body.append(h("tr", {},
        h("td", {}, new Date(it.created_at).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })),
        h("td", {}, MODULE_LABEL[it.module] || it.module),
        h("td", { class: "in", title: it.input_text }, it.input_text),
        h("td", {}, String(it.score)),
        h("td", {}, h("span", { class: "dot " + color }), it.level),
        h("td", {}, it.confidence != null ? it.confidence + "%" : "–"),
        h("td", { class: "act" },
          h("button", { class: "icon-btn", type: "button", onclick: () => viewCheck(it.id) }, "View"),
          h("button", { class: "icon-btn del", type: "button", onclick: () => deleteCheck(it.id) }, "Delete"))));
    });
    $("#usage-text").textContent = `${data.used} / ${data.limit} used`;
    const fill = $("#usage-fill"); fill.style.width = Math.min(100, data.used / data.limit * 100) + "%"; fill.classList.toggle("full", data.used >= data.limit);
    $("#history-hint").textContent = data.used >= data.limit
      ? "History is full — the oldest check is deleted automatically when you add a new one. You can also delete items or clear all."
      : `Only you can see these. Oldest checks are removed automatically after ${data.limit}.`;
    if (!module && !q) {
      $("#stat-total").textContent = data.used;
      $("#stat-risky").textContent = data.items.filter(i => i.module !== "resume" && colorFor(i.level) === "red").length;
    }
  } catch { /* logged out or offline */ }
}
async function viewCheck(id) {
  try { renderResult(await api(`/api/history/${id}`)); $("#verify").scrollIntoView({ behavior: "smooth" }); } catch (e) { toast(e.message); }
}
async function deleteCheck(id) {
  try { await api(`/api/history/${id}`, { method: "DELETE" }); toast("Check deleted"); loadHistory(); } catch (e) { toast(e.message); }
}
$("#clear-history").addEventListener("click", async () => {
  if (!confirm("Delete ALL your saved checks? This cannot be undone.")) return;
  try { const d = await api("/api/history", { method: "DELETE" }); toast(`${d.deleted} check(s) deleted`); loadHistory(); } catch (e) { toast(e.message); }
});
$("#history-filter").addEventListener("change", loadHistory);
$("#history-search").addEventListener("input", () => { clearTimeout(historyTimer); historyTimer = setTimeout(loadHistory, 250); });

/* ------------------------------------------------------------------ accuracy */
async function loadMetrics() {
  try {
    const m = await api("/api/model-info");
    $("#stat-acc").textContent = m.accuracy + "%";
    const box = $("#metrics"); box.replaceChildren();
    [["Accuracy", m.accuracy], ["Precision", m.precision], ["Recall", m.recall], ["F1 score", m.f1]].forEach(([label, v]) => {
      const fill = h("i"); fill.style.width = v + "%";
      box.append(h("div", { class: "metric" }, h("b", {}, v + "%"), h("span", {}, label), h("div", { class: "bar" }, fill)));
    });
    $("#metrics-note").textContent = `Trained on ${m.train_samples} messages, tested on ${m.test_samples} unseen ones (5-fold cross-validation: ${m.cv_accuracy}%). ${m.note}`;
  } catch { /* ignore */ }
}

/* ------------------------------------------------------------------ start */
(async function init() {
  try { const { user } = await api("/api/auth/me"); user ? showApp(user) : showAuth(); }
  catch { showAuth(); }
})();
