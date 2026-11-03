// Loaded only when gui.html is served to a browser (web.py injects it).
// Provides the same window.pywebview.api the desktop app has, but over a WebSocket,
// so gui.html runs unchanged on phones.
(() => {
  let ws = null, rid = 0, joined = null, reconnecting = false;
  const pending = new Map();
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  function open() {
    return new Promise((resolve, reject) => {
      const sock = new WebSocket(`wss://${location.host}/ws`);
      sock.onopen = () => { ws = sock; resolve(); };
      sock.onerror = reject;
      sock.onclose = () => { if (ws === sock) lost(); };
      sock.onmessage = e => {
        const m = JSON.parse(e.data);
        if (m.event) window.onMessage(m.event);
        else if (pending.has(m.rid)) { pending.get(m.rid)(m.result); pending.delete(m.rid); }
      };
    });
  }

  function call(name, ...args) {
    return new Promise(resolve => {
      if (!ws || ws.readyState !== WebSocket.OPEN) return resolve(null);
      const id = ++rid;
      pending.set(id, resolve);
      ws.send(JSON.stringify({rid: id, call: name, args}));
    });
  }

  async function join(name, password, server) {
    const r = await call("join", name, password, server);
    if (r && r.ok) joined = [name, password];
    return r;
  }

  // phone locked, Wi-Fi blip, server restart: rejoin with the same name and password
  async function lost() {
    ws = null;
    pending.forEach(resolve => resolve(null));
    pending.clear();
    if (!joined || reconnecting) return;
    reconnecting = true;
    window.onMessage({type: "status", state: "reconnecting"});
    for (;;) {
      await sleep(2000);
      try { await open(); } catch { continue; }
      const r = await call("join", ...joined, "");
      if (r && r.ok) {
        reconnecting = false;
        window.onMessage({type: "status", state: "connected"});
        return;
      }
      // a taken name is usually our own ghost session, which the server drops shortly
      if (r && !/taken|full/.test(r.error)) {
        reconnecting = false;
        window.onMessage({type: "status", state: "offline"});
        window.onMessage({type: "error", text: r.error});
        return;
      }
      const s = ws; ws = null; s && s.close();
    }
  }

  // the server drops a socket that's silent for 30 s
  setInterval(() => ws && ws.readyState === WebSocket.OPEN && ws.send('{"call":"noop"}'), 10000);

  const api = new Proxy({}, {get: (_, name) => name === "join" ? join : (...args) => call(name, ...args)});
  window.pywebview = {api};

  // an invite QR code carries the password after '#', which browsers never send to the server
  const pw = new URLSearchParams(location.hash.slice(1)).get("pw");
  if (pw) {
    document.getElementById("passIn").value = pw;
    history.replaceState(null, "", location.pathname);  // don't leave it in the address bar
  }

  open().then(() => window.dispatchEvent(new Event("pywebviewready")),
              () => { document.getElementById("joinErr").textContent = "Can't reach the server. Reload to retry."; });
})();
