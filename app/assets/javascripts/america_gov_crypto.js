(() => {
  const STORAGE_KEYS = {
    dpopJwk: "agov_dpop_private_jwk",
    siteKeyPriv: "agov_site_key_private_jwk",
    siteKeyPub: "agov_site_key_public_jwk",
  };

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function b64uEncode(bytes) {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let bin = "";
    for (let i = 0; i < arr.length; i += 1) {
      bin += String.fromCharCode(arr[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function b64uDecode(str) {
    const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
    const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/") + pad);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }

  function uint32BE(n) {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, n, false);
    return buf;
  }

  function concatBytes(...arrays) {
    const total = arrays.reduce((sum, a) => sum + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }

  async function jwkThumbprint(pubJwk) {
    const canonical = JSON.stringify({
      crv: pubJwk.crv,
      kty: pubJwk.kty,
      x: pubJwk.x,
      y: pubJwk.y,
    });
    return b64uEncode(await sha256(encoder.encode(canonical)));
  }

  async function getOrCreateDpopJwk() {
    const existing = sessionStorage.getItem(STORAGE_KEYS.dpopJwk);
    if (existing) {
      return JSON.parse(existing);
    }
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const privJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    sessionStorage.setItem(STORAGE_KEYS.dpopJwk, JSON.stringify(privJwk));
    return privJwk;
  }

  function publicPartOfJwk(jwk) {
    return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  }

  async function signDpopProof({ dpopJwk, htm, htu, accessToken = null }) {
    const pubJwk = publicPartOfJwk(dpopJwk);
    const header = { typ: "dpop+jwt", alg: "ES256", jwk: pubJwk };
    const payload = {
      jti: crypto.randomUUID(),
      htm,
      htu,
      iat: Math.floor(Date.now() / 1000),
    };
    if (accessToken) {
      payload.ath = b64uEncode(await sha256(encoder.encode(accessToken)));
    }

    const signingInput = `${b64uEncode(encoder.encode(JSON.stringify(header)))}.${b64uEncode(
      encoder.encode(JSON.stringify(payload)),
    )}`;
    const ecdsaKey = await crypto.subtle.importKey(
      "jwk",
      dpopJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      ecdsaKey,
      encoder.encode(signingInput),
    );
    return `${signingInput}.${b64uEncode(sig)}`;
  }

  // Matches SiteKeys::Sealer#seal (ECDH-ES direct + Concat KDF SHA-256 + AES-256-GCM)
  async function unsealSiteKeyJwe(compactJwe, dpopJwk, clientId) {
    const [headerB64, , ivB64, ctB64, tagB64] = compactJwe.split(".");
    const header = JSON.parse(decoder.decode(b64uDecode(headerB64)));
    if (header.alg !== "ECDH-ES" || header.enc !== "A256GCM") {
      throw new Error(`Unsupported JWE alg/enc: ${header.alg}/${header.enc}`);
    }

    const ecdhPrivJwk = { ...dpopJwk, key_ops: ["deriveBits"] };
    const ecdhPrivKey = await crypto.subtle.importKey(
      "jwk",
      ecdhPrivJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    const epkKey = await crypto.subtle.importKey(
      "jwk",
      { ...header.epk, ext: true },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const sharedSecret = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: epkKey }, ecdhPrivKey, 256),
    );

    const encBytes = encoder.encode(header.enc);
    const clientBytes = encoder.encode(clientId);
    const otherInfo = concatBytes(
      uint32BE(encBytes.length),
      encBytes,
      uint32BE(0),
      uint32BE(clientBytes.length),
      clientBytes,
      uint32BE(256),
    );
    const kdfInput = concatBytes(uint32BE(1), sharedSecret, otherInfo);
    const cekBytes = await sha256(kdfInput);

    const aesKey = await crypto.subtle.importKey("raw", cekBytes, { name: "AES-GCM" }, false, [
      "decrypt",
    ]);
    const combinedCt = concatBytes(b64uDecode(ctB64), b64uDecode(tagB64));
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64uDecode(ivB64),
        additionalData: encoder.encode(headerB64),
      },
      aesKey,
      combinedCt,
    );
    return JSON.parse(decoder.decode(plaintext));
  }

  // Matches AmericaGov::ServerSealer (ECDH + SHA-256 KDF bound to user_sub + AES-256-GCM)
  async function deriveItemKey(sharedSecret, userSub) {
    const subBytes = encoder.encode(userSub);
    const algInfo = encoder.encode("A256GCM");
    const input = concatBytes(
      uint32BE(1),
      sharedSecret,
      uint32BE(subBytes.length),
      subBytes,
      algInfo,
    );
    const keyBytes = await sha256(input);
    return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  async function encryptConversationItem(payload, siteKeyPubJwk, userSub) {
    const ephPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    const epkRaw = await crypto.subtle.exportKey("jwk", ephPair.publicKey);
    const epk = publicPartOfJwk(epkRaw);

    const recipientPub = await crypto.subtle.importKey(
      "jwk",
      { ...siteKeyPubJwk, ext: true },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const sharedSecret = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: recipientPub }, ephPair.privateKey, 256),
    );
    const aesKey = await deriveItemKey(sharedSecret, userSub);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = b64uEncode(encoder.encode(JSON.stringify(epk)));
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: encoder.encode(aad) },
        aesKey,
        encoder.encode(JSON.stringify(payload)),
      ),
    );

    return {
      kind: payload.kind || "chat",
      source: "browser",
      epk,
      iv: b64uEncode(iv),
      aad,
      ciphertext: b64uEncode(encrypted),
    };
  }

  async function decryptConversationItem(item, siteKeyPrivJwk, userSub) {
    const privKey = await crypto.subtle.importKey(
      "jwk",
      { ...siteKeyPrivJwk, key_ops: ["deriveBits"] },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    const epk = await crypto.subtle.importKey(
      "jwk",
      { ...item.epk, ext: true },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const sharedSecret = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, privKey, 256),
    );
    const aesKey = await deriveItemKey(sharedSecret, userSub);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64uDecode(item.iv),
        additionalData: encoder.encode(item.aad),
      },
      aesKey,
      b64uDecode(item.ciphertext),
    );
    return JSON.parse(decoder.decode(decrypted));
  }

  async function postJson(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken(),
        Accept: "application/json",
      },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
  }

  function setStatus(text, level = "info") {
    const banner = document.getElementById("agov-status-banner");
    const msg = document.getElementById("agov-status-text");
    if (!banner || !msg) return;
    banner.className = `usa-alert usa-alert--${level} margin-bottom-2`;
    msg.textContent = text;
  }

  function renderTelemetry({ dpopThumbprint, siteKeyPub, unlocked }) {
    const dpopEl = document.getElementById("agov-dpop-jkt");
    const pubEl = document.getElementById("agov-site-key-pub");
    const stateEl = document.getElementById("agov-key-state");
    if (dpopEl) dpopEl.textContent = dpopThumbprint || "—";
    if (pubEl) pubEl.textContent = siteKeyPub ? JSON.stringify(siteKeyPub) : "—";
    if (stateEl) {
      stateEl.textContent = unlocked
        ? "Unlocked in Browser Memory (Private scalar never leaves browser)"
        : "Locked / Not loaded";
    }
  }

  function buildMessageElement(decrypted, rawItem) {
    const wrapper = document.createElement("div");
    let mod = "";
    if (rawItem.source === "server_sealed") mod = " agov-msg--server";
    else if (decrypted.kind === "widget_ticket") mod = " agov-msg--widget";
    else if (decrypted.sender && decrypted.sender.includes("Assistant")) mod = " agov-msg--assistant";

    wrapper.className = `agov-msg${mod}`;

    const meta = document.createElement("div");
    meta.className = "agov-msg__meta";
    const left = document.createElement("strong");
    left.textContent = decrypted.sender || "You";
    const right = document.createElement("span");
    right.textContent = `${rawItem.source} · ${new Date(rawItem.created_at).toLocaleTimeString()}`;
    meta.append(left, right);
    wrapper.appendChild(meta);

    if (decrypted.title) {
      const titleEl = document.createElement("div");
      titleEl.className = "text-bold margin-bottom-05";
      titleEl.textContent = decrypted.title;
      wrapper.appendChild(titleEl);
    }

    const bodyEl = document.createElement("div");
    bodyEl.textContent = decrypted.body || "";
    wrapper.appendChild(bodyEl);

    return wrapper;
  }

  async function refreshConversations(config) {
    const logEl = document.getElementById("agov-chat-log");
    const rawEl = document.getElementById("agov-raw-json");
    if (!logEl || !rawEl) return;

    const res = await fetch("/api/conversations", { headers: { Accept: "application/json" } });
    if (!res.ok) return;
    const data = await res.json();
    rawEl.textContent = data.raw_store_json || "[]";

    const privRaw = sessionStorage.getItem(STORAGE_KEYS.siteKeyPriv);
    if (!privRaw) {
      logEl.textContent = "Site key not unlocked in this browser session yet.";
      return;
    }
    const siteKeyPriv = JSON.parse(privRaw);

    logEl.innerHTML = "";
    if (data.items.length === 0) {
      const empty = document.createElement("p");
      empty.className = "text-base margin-0";
      empty.textContent =
        "No encrypted messages yet. Send a chat message or create a client-side ticket to test zero-knowledge persistence.";
      logEl.appendChild(empty);
      return;
    }

    for (const item of data.items) {
      try {
        const decrypted = await decryptConversationItem(item, siteKeyPriv, config.userSub);
        logEl.appendChild(buildMessageElement(decrypted, item));
      } catch (err) {
        const errDiv = document.createElement("div");
        errDiv.className = "agov-msg";
        errDiv.textContent = `Unable to decrypt record ${item.id} (${err.message}) — likely created under an earlier site key before a reset.`;
        logEl.appendChild(errDiv);
      }
    }
    logEl.scrollTop = logEl.scrollHeight;
  }

  function assistantReplyFor(messageText) {
    const lower = messageText.toLowerCase();
    if (lower.includes("fraud") || lower.includes("scam")) {
      return "Fraud guidance: Do not share one-time codes. Use the Client-Side Intake Widget below to log sensitive incident details—your browser encrypts the ticket before saving.";
    }
    if (lower.includes("ssa") || lower.includes("benefit")) {
      return "Benefits guidance: Your estimated SSA calculation runs locally in browser memory. Any saved summary is encrypted with your Login.gov Site Key.";
    }
    return `Received locally (${messageText.length} chars). Both your prompt and this reply were encrypted in your browser before touching America.gov's JSON store.`;
  }

  async function completeDpopHandoff(config) {
    setStatus("Completing DPoP token exchange and unsealing your Login.gov Site Key in browser...", "info");
    const dpopJwk = await getOrCreateDpopJwk();

    const tokenProof = await signDpopProof({
      dpopJwk,
      htm: "POST",
      htu: config.tokenEndpoint,
    });
    const tokenData = await postJson("/auth/dpop_token", { dpop_proof: tokenProof });

    const userinfoProof = await signDpopProof({
      dpopJwk,
      htm: "GET",
      htu: config.userinfoEndpoint,
      accessToken: tokenData.access_token,
    });
    const userinfo = await postJson("/auth/dpop_userinfo", { dpop_proof: userinfoProof });

    if (userinfo.site_key && userinfo.site_key_public) {
      const unsealedPrivJwk = await unsealSiteKeyJwe(
        userinfo.site_key,
        dpopJwk,
        config.clientId,
      );
      sessionStorage.setItem(STORAGE_KEYS.siteKeyPriv, JSON.stringify(unsealedPrivJwk));
      sessionStorage.setItem(STORAGE_KEYS.siteKeyPub, JSON.stringify(userinfo.site_key_public));
      window.location.reload();
    } else {
      setStatus(
        "Signed in, but Login.gov did not return a site_key claim. Ensure site_key scope was requested and Login.gov config is enabled.",
        "warning",
      );
    }
  }

  function wireLoginFormDpop() {
    const form = document.querySelector('form[action="/auth/request"]');
    if (!form) return;

    form.addEventListener("submit", async (event) => {
      const siteKeyBox = form.querySelector('input[name="requested_scopes[]"][value="site_key"]');
      if (siteKeyBox && !siteKeyBox.checked) return;

      if (form.dataset.dpopPrepared === "true") return;
      event.preventDefault();

      const dpopJwk = await getOrCreateDpopJwk();
      const thumbprint = await jwkThumbprint(publicPartOfJwk(dpopJwk));

      let hidden = form.querySelector('input[name="dpop_jkt"]');
      if (!hidden) {
        hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "dpop_jkt";
        form.appendChild(hidden);
      }
      hidden.value = thumbprint;
      form.dataset.dpopPrepared = "true";
      form.submit();
    });
  }

  function wireLogoutCleanup() {
    const logoutForm = document.querySelector('form[action="/handle-logout"]');
    if (!logoutForm) return;
    logoutForm.addEventListener("submit", () => {
      Object.values(STORAGE_KEYS).forEach((k) => sessionStorage.removeItem(k));
    });
  }

  function wirePortalActions(config) {
    const chatForm = document.getElementById("agov-chat-form");
    const chatInput = document.getElementById("agov-chat-input");
    const widgetForm = document.getElementById("agov-widget-form");
    const serverSealBtn = document.getElementById("agov-server-seal-btn");
    const clearBtn = document.getElementById("agov-clear-btn");

    const getPub = () => {
      const raw = sessionStorage.getItem(STORAGE_KEYS.siteKeyPub);
      return raw ? JSON.parse(raw) : config.siteKeyPublic;
    };

    if (chatForm && chatInput) {
      chatForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const text = chatInput.value.trim();
        const pub = getPub();
        if (!text || !pub) return;
        chatInput.value = "";

        const userItem = await encryptConversationItem(
          {
            kind: "chat",
            sender: `You (${config.userEmail || "User"})`,
            body: text,
            timestamp: new Date().toISOString(),
          },
          pub,
          config.userSub,
        );
        await postJson("/api/conversations", { conversation: userItem });

        const botItem = await encryptConversationItem(
          {
            kind: "chat",
            sender: "America.gov Assistant",
            body: assistantReplyFor(text),
            timestamp: new Date().toISOString(),
          },
          pub,
          config.userSub,
        );
        await postJson("/api/conversations", { conversation: botItem });
        await refreshConversations(config);
      });
    }

    if (widgetForm) {
      widgetForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const pub = getPub();
        if (!pub) return;

        const category = document.getElementById("agov-widget-category").value;
        const amount = document.getElementById("agov-widget-amount").value;
        const details = document.getElementById("agov-widget-details").value.trim();
        if (!details) return;

        const ticketItem = await encryptConversationItem(
          {
            kind: "widget_ticket",
            sender: "Client-Side Intake Widget (Browser-Only)",
            title: `${category} — Est. Value/Impact: $${amount || "0"}`,
            body: details,
            timestamp: new Date().toISOString(),
          },
          pub,
          config.userSub,
        );
        await postJson("/api/conversations", { conversation: ticketItem });
        document.getElementById("agov-widget-details").value = "";
        await refreshConversations(config);
      });
    }

    if (serverSealBtn) {
      serverSealBtn.addEventListener("click", async () => {
        await postJson("/api/conversations/server_sealed", {});
        await refreshConversations(config);
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", async () => {
        await fetch("/api/conversations", {
          method: "DELETE",
          headers: { "X-CSRF-Token": csrfToken(), Accept: "application/json" },
        });
        await refreshConversations(config);
      });
    }
  }

  document.addEventListener("DOMContentLoaded", async () => {
    wireLoginFormDpop();
    wireLogoutCleanup();

    const configEl = document.getElementById("america-gov-config");
    if (!configEl) return;
    const config = JSON.parse(configEl.textContent);

    if (config.pendingDpop) {
      try {
        await completeDpopHandoff(config);
      } catch (err) {
        setStatus(`DPoP handoff failed: ${err.message}`, "error");
      }
      return;
    }

    if (config.userSub) {
      const dpopRaw = sessionStorage.getItem(STORAGE_KEYS.dpopJwk);
      const thumbprint = dpopRaw
        ? await jwkThumbprint(publicPartOfJwk(JSON.parse(dpopRaw)))
        : config.dpopJkt;
      const privRaw = sessionStorage.getItem(STORAGE_KEYS.siteKeyPriv);
      const pubRaw = sessionStorage.getItem(STORAGE_KEYS.siteKeyPub);
      const siteKeyPub = pubRaw ? JSON.parse(pubRaw) : config.siteKeyPublic;

      renderTelemetry({
        dpopThumbprint: thumbprint,
        siteKeyPub,
        unlocked: Boolean(privRaw),
      });

      if (privRaw) {
        setStatus(
          "Site Key unsealed in browser memory via WebCrypto. All history is encrypted client-side before leaving your browser.",
          "success",
        );
      } else {
        setStatus(
          "Authenticated, but Site Key is not in this tab's sessionStorage. Sign out and sign back in with site_key scope.",
          "warning",
        );
      }

      wirePortalActions(config);
      await refreshConversations(config);
    }
  });
})();
