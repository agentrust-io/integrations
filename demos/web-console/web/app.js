"use strict";
const $ = (s) => document.querySelector(s);
const api = async (path, body) => (await fetch(path, body
  ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
  : {})).json();
// Quotes too: several values land inside attribute values, not only text.
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let CTX = null;
let selected = "clean";
let variant = "approved";     // which Cedar bundle the gateway loaded
let reasonMap = {};
let lastRun = null;

function showView(name) {
  document.querySelectorAll(".navitem").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
}
document.querySelectorAll(".navitem").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));

async function boot() {
  CTX = await api("/api/context");
  $("#gw-status").textContent = "gateway " + CTX.gateway.replace(/^https?:\/\//, "");
  CTX.guardrails.forEach((g) => (reasonMap[g.reason] = g));

  // scenarios
  $("#scenarios").innerHTML = CTX.scenarios.map((s) => `
    <button class="scn${s.id === selected ? " sel" : ""}" data-id="${esc(s.id)}">
      <div class="label">${esc(s.label)}</div>
      <div class="obligor">${esc(s.obligor)}</div>
      <div class="amt">${esc(s.amount)}</div>
      <span class="exp ${esc(s.outcome)}">${esc(s.expect)}</span>
    </button>`).join("");
  document.querySelectorAll(".scn").forEach((c) => c.addEventListener("click", () => {
    selected = c.dataset.id;
    document.querySelectorAll(".scn").forEach((x) => x.classList.toggle("sel", x === c));
  }));

  // policy variant -- approved bundle, or the one an operator quietly edited
  renderVariant();
  document.querySelectorAll(".var").forEach((b) => b.addEventListener("click", () => {
    variant = b.dataset.variant;
    renderVariant();
  }));
  $("#tamper-edits").innerHTML = (CTX.tamper_edits || [])
    .map((e) => `<li>${esc(e)}</li>`).join("");

  // guardrails + policy
  $("#guardrails").innerHTML = CTX.guardrails.map((g) =>
    `<div class="gr"><span class="reg">${esc(g.regulation)}</span><span class="plain">${esc(g.plain)}</span></div>`).join("");
  $("#policy").textContent = CTX.policy.trim();

  // tools
  $("#tools").innerHTML = CTX.tools.map((t) =>
    `<div class="trow"><code>${esc(t.tool_name)}</code><span class="dom ${esc(t.compliance_domain)}">${esc(t.compliance_domain)}</span><span class="desc">${esc(t.description)}</span></div>`).join("");
}

function renderVariant() {
  document.querySelectorAll(".var").forEach((b) =>
    b.classList.toggle("sel", b.dataset.variant === variant));
  const h = (CTX.policy_hashes || {})[variant] || "";
  $("#variant-hash").textContent = h;
  $("#tamper-note").className = variant === "tampered" ? "tamper show" : "tamper";
}

async function run() {
  const btn = $("#run");
  btn.disabled = true; btn.textContent = "Running…"; $("#run-hint").textContent = "";
  $("#timeline").innerHTML = ""; $("#summary").className = "summary hide";
  try {
    const r = await api("/api/run", { scenario: selected, variant });
    lastRun = r;
    renderRun(r);
  } catch (e) {
    $("#run-hint").textContent = "run failed -- is the gateway up?";
  } finally {
    btn.disabled = false; btn.textContent = "Run assessment";
  }
}

function renderRun(r) {
  const steps = r.steps || [];
  const sum = $("#summary");

  // A crashed or partial run is an error, not a pass. Inferring "allowed" from
  // the absence of a denied write used to render a failure as a green success.
  if (r.error) {
    sum.className = "summary deny";
    sum.innerHTML = `<span class="st">Run failed.</span> ${esc(r.error.split("\n")[0])}
      <pre class="mut" style="margin-top:6px;white-space:pre-wrap">${esc(r.error.split("\n").slice(1).join("\n"))}</pre>`;
    $("#timeline").innerHTML = "";
    return;
  }

  const write = steps.find((s) => s.tool && s.tool.endsWith("risk_report_writer"));
  const denied = write && write.decision === "deny";
  // A write that only succeeded because the bundle was edited is not a success.
  // Colour it as the warning it is, not the green of a clean pass.
  const tamperedAllow = !denied && r.variant === "tampered";
  sum.className = "summary " + (denied ? "deny" : tamperedAllow ? "tampered" : "allow");
  if (denied) {
    const reason = write.advice.reason || "";
    const g = reasonMap[reason];
    sum.innerHTML = `<span class="st">Write blocked.</span> ${esc(g ? g.plain : reason)}
      <span class="reg">${esc(write.advice.regulation || (g && g.regulation) || "")}</span>
      <div class="mut" style="margin-top:6px">The risk report was not written to core banking.</div>`;
  } else if (r.variant === "tampered") {
    sum.innerHTML = `<span class="st">Write allowed — under the tampered bundle.</span>
      The same facility that the approved policy refused was just written to core banking.
      <div class="mut" style="margin-top:6px">The enforcement worked exactly as the loaded policy told it to. That is why the record has to prove <em>which</em> policy was loaded.</div>`;
  } else {
    sum.innerHTML = `<span class="st">Assessment recorded.</span> All six steps passed policy; the report was written to core banking under Cedar enforcement.`;
  }

  $("#timeline").innerHTML = steps.map((s) => {
    const dec = s.decision || "allow";
    const adv = (dec === "deny" && (s.advice.regulation || s.advice.reason)) ? `
      <div class="adv"><span>${esc((reasonMap[s.advice.reason] || {}).plain || s.advice.reason || "denied by policy")}</span>
      ${s.advice.regulation ? `<span class="reg">${esc(s.advice.regulation)}</span>` : ""}</div>` : "";
    return `<li class="tl ${dec}">
      <span class="num">${s.n}/6</span>
      <span class="body"><span class="toolname">${esc(s.tool)}</span>
        ${s.note ? `<div class="note">${esc(s.note)}</div>` : ""}${adv}</span>
      <span class="pill">${dec === "deny" ? "403 denied" : "200 allow"}</span>
    </li>`;
  }).join("");
  // staggered reveal
  document.querySelectorAll("#timeline .tl").forEach((el, i) => setTimeout(() => el.classList.add("in"), 90 + i * 130));

  // record view
  if (r.claim) {
    $("#record").textContent = JSON.stringify(r.claim, null, 2);
    $("#verify").disabled = false;
    $("#rec-hint").textContent = "";
  }
}

async function verify() {
  // Always verify against the APPROVED bundle hash. A verifier that approved
  // one policy does not get to move the goalposts afterwards.
  const v = await api("/api/verify", { pinned: true });
  if (v.error) { $("#verify-result").innerHTML = `<div class="rslt">${esc(v.error)}</div>`; return; }
  $("#verify-checks").innerHTML = (v.checks || []).map((c) => {
    const p = c.status === "PASS";
    return `<div class="check ${p ? "pass" : "fail"}"><span class="box">${p ? "✓" : "✗"}</span><span class="name">${esc(c.name)}</span><span class="st">${c.status}</span></div>`;
  }).join("");

  const tampered = lastRun && lastRun.variant === "tampered";
  let html = "";
  if (tampered) {
    html += `<div class="rslt tampered"><b>policy_bundle.hash &mdash; FAIL</b><br>
      This record came from the tampered bundle. A verifier holding the approved
      hash rejects it, and no edit to the record can make the two agree.</div>`;
  }
  if (v.result) {
    const ok = v.result.detail === "verified";
    html += `<div class="rslt ${ok ? "verified" : "partial"}"><b>${esc(v.result.detail)}</b> &mdash; software-only run; on real TDX / SEV-SNP the hardware check verifies too.</div>`;
  }
  if (v.pinned_hash) {
    html += `<div class="rslt pinned">pinned to approved bundle<br><code>${esc(v.pinned_hash)}</code></div>`;
  }
  $("#verify-result").innerHTML = html;
}

$("#run").addEventListener("click", run);
$("#verify").addEventListener("click", verify);
boot();
