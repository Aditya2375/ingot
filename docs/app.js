/* app.js - drives two in-page ingot nodes via the wasm build. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const logEl = $("log");
  let M = null;

  function log(msg, cls) {
    const d = document.createElement("div");
    if (cls) d.className = cls;
    d.textContent = msg;
    logEl.appendChild(d);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function state(n) { return JSON.parse(M.ccall("w_state", "string", ["number"], [n])); }

  function render() {
    for (const n of [0, 1]) {
      const s = state(n);
      const L = n ? "B" : "A";
      $("bal" + L).textContent = s.balance.toFixed(1);
      $("h" + L).textContent = s.height;
      $("mp" + L).textContent = s.mempool;
      const bl = $("blocks" + L);
      bl.innerHTML = "";
      for (const b of s.blocks.slice().reverse()) {
        const row = document.createElement("div");
        row.className = "blk";
        const h = document.createElement("span");
        h.className = "h";
        h.textContent = "#" + b.height;
        const hash = document.createElement("span");
        hash.textContent = b.hash + "...";
        const txs = document.createElement("span");
        txs.textContent = b.txs + " tx";
        row.append(h, hash, txs);
        bl.appendChild(row);
      }
    }
  }

  function maybeSync() {
    if (!$("link").checked) return;
    const r = JSON.parse(M.ccall("w_sync", "string", [], []));
    if (r.moved) log("gossip: " + r.moved + " block(s) delivered" + (r.reorg ? ", reorg!" : ""), r.reorg ? "ok" : "dim");
  }

  function mine(n) {
    const r = JSON.parse(M.ccall("w_mine", "string", ["number"], [n]));
    const L = n ? "B" : "A";
    if (r.ok) {
      log(L + " mined block " + r.height + " " + r.hash.slice(0, 16) + "...", "ok");
      maybeSync();
    } else {
      log(L + " mine failed: " + r.err, "bad");
    }
    render();
  }

  function send(n) {
    const L = n ? "B" : "A";
    const amt = parseFloat($(n ? "amtB" : "amtA").value);
    const r = JSON.parse(M.ccall("w_send", "string", ["number", "number", "number"], [n, 1 - n, amt]));
    if (r.ok) {
      log(L + " signs " + amt + " INGOT to " + (n ? "A" : "B") + " (tx " + r.txid.slice(0, 16) + "..., in mempool)", "ok");
      maybeSync();
      log("tip: mine a block to confirm it" + ($("link").checked ? "" : ", and sync to deliver it"), "dim");
    } else {
      log(L + " send rejected: " + r.err, "bad");
    }
    render();
  }

  function tamper(n) {
    const s = state(n);
    if (s.height < 1) { log("nothing to forge yet - mine a few blocks first", "dim"); return; }
    const h = Math.max(1, s.height - 2);
    const r = JSON.parse(M.ccall("w_tamper", "string", ["number", "number"], [n, h]));
    log("forgery attempt on block " + h + " (coinbase +10): rejected - " + r.err, "bad");
    render();
  }

  function doSync() {
    const r = JSON.parse(M.ccall("w_sync", "string", [], []));
    log("sync: A=" + r.a + " B=" + r.b + (r.moved ? " (" + r.moved + " block(s) moved" + (r.reorg ? ", reorg" : "") + ")" : " (already in sync)") , r.reorg ? "ok" : "dim");
    render();
  }

  createIngot().then(function (m) {
    M = m;
    const s0 = (crypto.getRandomValues(new Uint32Array(1))[0]) || 1;
    const s1 = (crypto.getRandomValues(new Uint32Array(1))[0]) || 2;
    M.ccall("w_init", "number", ["number", "number"], [s0, s1]);
    $("addrA").textContent = M.ccall("w_address", "string", ["number"], [0]);
    $("addrB").textContent = M.ccall("w_address", "string", ["number"], [1]);
    document.querySelectorAll("[data-mine]").forEach((b) =>
      b.addEventListener("click", () => mine(+b.dataset.mine)));
    document.querySelectorAll("[data-send]").forEach((b) =>
      b.addEventListener("click", () => send(+b.dataset.send)));
    document.querySelectorAll("[data-tamper]").forEach((b) =>
      b.addEventListener("click", () => tamper(+b.dataset.tamper)));
    $("sync").addEventListener("click", doSync);
    $("net").textContent = "ready - both nodes booted from the same genesis";
    log("two nodes booted from the same genesis block", "dim");
    render();
  });
})();
