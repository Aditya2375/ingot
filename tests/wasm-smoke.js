/* Smoke test for the wasm demo build: boots the module and drives the same
 * API the page uses - mine, send, sync, fork + reorg, forgery rejection.
 * Run after sh wasm/build.sh: node tests/wasm-smoke.js [path/to/ingot.js] */
const factory = require(process.argv[2] || require("path").join(__dirname, "..", "docs", "ingot.js"));
let fails = 0;
function ok(cond, label) {
    if (cond) console.log("ok: " + label);
    else { console.log("FAIL: " + label); fails = 1; }
}
factory().then(m => {
    const J = (name, ...args) => JSON.parse(m.ccall("w_" + name, "string",
        ["number", "number", "number"].slice(0, args.length), args));
    const addr = (n) => m.ccall("w_address", "string", ["number"], [n]);

    m.ccall("w_init", "number", ["number", "number"], [111, 222]);
    ok(!J("send", 0, 1, NaN).ok && !J("send", 0, 1, Infinity).ok && !J("send", 0, 1, -1).ok && !J("send", 0, 1, 1000001).ok, "nonfinite, negative and oversized demo amounts rejected");
    ok(!J("send", -1, 1, 10).ok && !J("state", 2).ok, "invalid demo node indices rejected");
    const a = addr(0), b = addr(1);
    ok(a[0] === "i" && b[0] === "i" && a !== b, "both wallets boot with i-addresses");

    ok(J("mine", 0).ok && J("mine", 0).ok, "node A mines two blocks");
    const s = J("send", 0, 1, 10);
    ok(s.ok && s.mempool === 1, "A signs 10 coins to B into the mempool");
    ok(J("mine", 0).ok, "A mines the spend");
    const sy = J("sync");
    ok(sy.a === 3 && sy.b === 3 && sy.moved === 3, "sync delivers A's chain to B");
    ok(!sy.reorg, "ordinary chain extension is not called a reorg");
    const st = J("state", 1);
    ok(Math.abs(st.balance - 10) < 1e-9, "B sees its 10 coins after the sync");
    ok(st.mempool === 0, "the mined spend left both mempools");

    const t = J("tamper", 1, 1);
    ok(!t.ok && /proof of work|merkle|coinbase/.test(t.err),
       "a forged old block is rejected: " + t.err);

    ok(J("mine", 0).ok, "A privately mines its own divergent fourth block");
    ok(J("mine", 1).ok && J("mine", 1).ok && J("mine", 1).ok && J("mine", 1).ok,
       "B privately mines four blocks");
    const re = J("sync");
    ok(re.a === 7 && re.b === 7 && re.reorg, "the longer fork wins and reorgs A");
    const sa = J("state", 0), sb = J("state", 1);
    ok(sa.tip === sb.tip, "both nodes agree on the tip after the reorg");

    process.exit(fails);
});
