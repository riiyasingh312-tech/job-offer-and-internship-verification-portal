// Frontend logic: talks to the Flask API and renders results.
const API = location.protocol === "file:" ? "http://127.0.0.1:5000" : "";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const MODULE_LABEL = { company: "Company", offer_letter: "Offer letter", message: "Message", url: "URL" };
const VERDICT = {
  green: "Nothing alarming found — but always confirm through the company's official website.",
  amber: "Some warning signs found. Verify carefully before sharing documents or money.",
  red: "Strong scam indicators. Do NOT pay money or share personal documents.",
};

function colorFor(level) {
  if (level.startsWith("Likely Genuine")) return "green";
  if (level.startsWith("Suspicious")) return "amber";
  return "red";
}
const CSS_COLOR = { green: "#02c39a", amber: "#f2b134", red: "#d64550" };

/* ---------------- tabs ---------------- */
const TAB_TO_PANEL = { company: "panel-company", offer: "panel-offer", message: "panel-message", url: "panel-url" };
$$(".tab").forEach(btn => btn.addEventListener("click", () => {
  $$(".tab").forEach(b => b.classList.toggle("active", b === btn));
  $$(".panel").forEach(p => p.classList.toggle("active", p.id === TAB_TO_PANEL[btn.dataset.tab]));
  showOnly("result-empty");
}));

/* ---------------- example fillers ---------------- */
$$("[data-fill]").forEach(a => a.addEventListener("click", e => {
  e.preventDefault();
  const data = JSON.parse(a.dataset.fill);
  const form = a.closest("form");
  Object.entries(data).forEach(([k, v]) => { form.elements[k].value = v; });
}));

/* ---------------- offer letter: pdf / text toggle + drag & drop ---------------- */
let offerMode = "pdf";
$$(".seg").forEach(seg => seg.addEventListener("click", () => {
  offerMode = seg.dataset.mode;
  $$(".seg").forEach(s => s.classList.toggle("active", s === seg));
  $("#drop").classList.toggle("hidden", offerMode !== "pdf");
  $("#offer-text-wrap").classList.toggle("hidden", offerMode !== "text");
}));
const fileInput = $("#file-input");
fileInput.addEventListener("change", () => {
  $("#file-name").textContent = fileInput.files[0] ? fileInput.files[0].name : "Choose a PDF or drag it here";
});
const drop = $("#drop");
["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", e => {
  if (e.dataTransfer.files.length) { fileInput.files = e.dataTransfer.files; fileInput.dispatchEvent(new Event("change")); }
});

/* ---------------- result rendering ---------------- */
function showOnly(id) {
  ["result-empty", "result-loading", "result-out", "result-err"].forEach(x => $("#" + x).classList.toggle("hidden", x !== id));
}

function renderResult(r) {
  const color = colorFor(r.risk_level);
  const gauge = $("#gauge");
  gauge.style.setProperty("--col", CSS_COLOR[color]);
  gauge.style.setProperty("--pct", r.risk_score);
  $("#score").textContent = r.risk_score;

  const badge = $("#level-badge");
  badge.textContent = (color === "green" ? "🟢 " : color === "amber" ? "🟡 " : "🔴 ") + r.risk_level;
  badge.className = "badge " + color;
  $("#verdict").textContent = VERDICT[color];

  const ul = $("#flags");
  ul.innerHTML = "";
  const flags = r.flags.length ? r.flags : ["No warning signs detected in the information provided."];
  flags.forEach(f => {
    const li = document.createElement("li");
    li.textContent = f;                     // textContent => user-supplied text can never inject HTML
    if (!r.flags.length) li.className = "ok";
    ul.appendChild(li);
  });
  showOnly("result-out");
}

function showError(msg) {
  $("#result-err").textContent = "⚠ " + msg;
  showOnly("result-err");
}

/* ---------------- submit ---------------- */
$$("form.panel").forEach(form => form.addEventListener("submit", async e => {
  e.preventDefault();
  const endpoint = form.dataset.endpoint;
  const btn = $("button[type=submit]", form);
  let options;

  if (endpoint === "offer-letter") {
    if (offerMode === "pdf") {
      if (!fileInput.files[0]) return showError("Please choose a PDF file first.");
      const fd = new FormData();
      fd.append("file", fileInput.files[0]);
      options = { method: "POST", body: fd };
    } else {
      const text = form.elements["text"].value.trim();
      if (!text) return showError("Please paste the offer letter text.");
      options = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) };
    }
  } else {
    const body = {};
    new FormData(form).forEach((v, k) => { body[k] = String(v).trim(); });
    options = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  }

  btn.disabled = true;
  showOnly("result-loading");
  try {
    const res = await fetch(`${API}/api/verify/${endpoint}`, options);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Something went wrong");
    renderResult(data);
    loadHistory();
    if (window.innerWidth <= 860) $("#result").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    const offline = err instanceof TypeError;
    showError(offline ? "Cannot reach the server. Make sure `python app.py` is running." : err.message);
  } finally {
    btn.disabled = false;
  }
}));

/* ---------------- history ---------------- */
async function loadHistory() {
  const tbody = $("#history-body");
  try {
    const res = await fetch(`${API}/api/history?limit=15`);
    const rows = await res.json();
    if (!rows.length) { tbody.innerHTML = '<tr><td colspan="5" class="muted">No checks yet.</td></tr>'; return; }
    tbody.innerHTML = "";
    rows.forEach(r => {
      const tr = document.createElement("tr");
      const color = colorFor(r.risk_level);
      const cells = [
        new Date(r.created_at).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }),
        MODULE_LABEL[r.module] || r.module,
        r.input_text || "",
        String(r.risk_score),
      ];
      cells.forEach((c, i) => {
        const td = document.createElement("td");
        td.textContent = c;
        if (i === 2) { td.className = "in"; td.title = c; }
        tr.appendChild(td);
      });
      const last = document.createElement("td");
      const dot = document.createElement("span");
      dot.className = "dot " + color;
      last.append(dot, document.createTextNode(r.risk_level));
      tr.appendChild(last);
      tbody.appendChild(tr);
    });
  } catch { /* server offline: leave table as is */ }
}
$("#refresh-history").addEventListener("click", loadHistory);
loadHistory();
