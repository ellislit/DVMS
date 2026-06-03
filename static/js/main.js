/**
 * main.js — Institutional Gate Pass & Visitor Management System
 * Vanilla JS only. Handles API fetches, DOM updates, and QR scanner logic.
 */

"use strict";

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

function showMessage(elementId, message, type = "info") {
  const el = document.getElementById(elementId);
  if (!el) return;
  const colors = {
    success: "bg-green-50 border-green-400 text-green-800",
    error:   "bg-red-50 border-red-400 text-red-800",
    warning: "bg-yellow-50 border-yellow-400 text-yellow-800",
    info:    "bg-blue-50 border-blue-400 text-blue-800",
  };
  el.className = `p-4 rounded-xl border text-sm font-medium ${colors[type] || colors.info}`;
  el.textContent = message;
  el.classList.remove("hidden");
  el.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function hideMessage(elementId) {
  const el = document.getElementById(elementId);
  if (el) el.classList.add("hidden");
}

function setButtonLoading(btn, loading, originalText) {
  if (loading) {
    btn.disabled = true;
    btn.dataset.original = btn.textContent;
    btn.textContent = "Processing…";
  } else {
    btn.disabled = false;
    btn.textContent = originalText || btn.dataset.original || "Submit";
  }
}

async function postJSON(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await resp.json();
  return { ok: resp.ok, status: resp.status, data };
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

(function initAuth() {
  const form = document.getElementById("auth-form");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideMessage("authMsg");
      const btn = form.querySelector("button[type=submit]");
      setButtonLoading(btn, true);
      const fd = new FormData(form);
      try {
        const { ok, data } = await postJSON("/api/login", {
          login_id: fd.get("login_id"),
          password: fd.get("password"),
        });
        if (ok) {
          showMessage("authMsg", data.message, "success");
          window.location.href = data.redirect || "/";
        } else {
          showMessage("authMsg", data.message || "Login failed.", "error");
        }
      } catch (err) {
        showMessage("authMsg", "Network error. Please try again.", "error");
      } finally {
        setButtonLoading(btn, false, "Sign in securely");
      }
    });
  }

  document.querySelectorAll("[data-logout]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await fetch("/api/logout", { method: "POST" });
      } finally {
        window.location.href = "/auth";
      }
    });
  });
})();

// ---------------------------------------------------------------------------
// Public Visitor Registration
// ---------------------------------------------------------------------------

(function initVisitorForm() {
  const form = document.getElementById("visitorForm");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideMessage("visitorMsg");
    const btn = form.querySelector("button[type=submit]");
    setButtonLoading(btn, true);

    const payload = {
      name:        form.name.value.trim(),
      national_id: form.national_id.value.trim(),
      phone:       form.phone.value.trim(),
      email:       form.email.value.trim(),
      visit_date:  form.visit_date.value,
      vehicle_reg: form.vehicle_reg ? form.vehicle_reg.value.trim() : "",
      department:  form.department.value,
      purpose:     form.purpose.value.trim(),
    };

    try {
      const { ok, data } = await postJSON("/api/visitor/request", payload);
      if (ok) {
        showMessage("visitorMsg", data.message, "success");
        form.reset();
      } else if (data.blacklisted) {
        showMessage("visitorMsg", "\uD83D\uDEAB ACCESS DENIED: " + data.message, "error");
      } else {
        showMessage("visitorMsg", data.message || "Submission failed.", "error");
      }
    } catch (err) {
      showMessage("visitorMsg", "Network error. Please try again.", "error");
    } finally {
      setButtonLoading(btn, false, "Submit Request");
    }
  });
})();

// ---------------------------------------------------------------------------
// Internal Requester: Submit Pass Request
// ---------------------------------------------------------------------------

(function initRequesterForm() {
  const form = document.getElementById("passRequestForm");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideMessage("passRequestMsg");
    const btn = form.querySelector("button[type=submit]");
    setButtonLoading(btn, true);

    const payload = {
      destination:         form.destination.value.trim(),
      visit_date:          form.visit_date.value,
      time_window:         form.time_window.value.trim(),
      reason:              form.reason.value.trim(),
      visitor_name:        form.visitor_name.value.trim(),
      visitor_national_id: form.visitor_national_id.value.trim(),
      visitor_phone:       form.visitor_phone.value.trim(),
      visitor_email:       form.visitor_email.value.trim(),
      visitor_vehicle_reg: form.visitor_vehicle_reg ? form.visitor_vehicle_reg.value.trim() : "",
    };

    try {
      const { ok, data } = await postJSON("/api/pass/request", payload);
      if (ok) {
        showMessage("passRequestMsg", data.message, "success");
        form.reset();
        setTimeout(() => window.location.reload(), 4000);
      } else {
        showMessage("passRequestMsg", data.message || "Submission failed.", "error");
      }
    } catch (err) {
      showMessage("passRequestMsg", "Network error. Please try again.", "error");
    } finally {
      setButtonLoading(btn, false, "Request Pass");
    }
  });
})();

// ---------------------------------------------------------------------------
// Requester: QR Code Modal Toggle
// ---------------------------------------------------------------------------

(function initQrModal() {
  const modal = document.getElementById("qrModal");
  if (!modal) return;

  document.querySelectorAll("[data-qr-open]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const src = btn.dataset.qrSrc || "";
      const title = "Gate Pass QR Code — Pass #" + (btn.dataset.qrOpen || "");
      document.getElementById("qrImage").src = src;
      document.getElementById("qrModalTitle").textContent = title;
      modal.classList.remove("hidden");

      // ── WhatsApp share button ────────────────────────────────────────────────
      const waBtn = document.getElementById("whatsappShareBtn");
      if (waBtn) {
        const token = btn.dataset.qrToken;
        const vName = btn.dataset.visitorName;
        const vPhone = btn.dataset.visitorPhone;
        const vDate = btn.dataset.visitDate;

        if (token && vName && vPhone && vDate) {
          const phoneClean = vPhone.replace(/[^\d+]/g, "");
          const waText = `Hello ${vName}, your Kabarak University Gate Pass token is: ${token}. Please present this at the main gate on ${vDate}.`;
          waBtn.href = `https://wa.me/${phoneClean}?text=${encodeURIComponent(waText)}`;
          waBtn.classList.remove("hidden");
        } else {
          waBtn.classList.add("hidden");
        }
      }
    });
  });

  const closeBtn = document.getElementById("qrModalClose");
  if (closeBtn) {
    closeBtn.addEventListener("click", () => modal.classList.add("hidden"));
  }

  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.classList.add("hidden");
  });
})();

// ---------------------------------------------------------------------------
// Admin: Tab switching
// ---------------------------------------------------------------------------

(function initAdminTabs() {
  const tabs = document.querySelectorAll("[data-admin-tab]");
  if (!tabs.length) return;

  function activateAdminTab(name) {
    tabs.forEach((btn) => {
      const active = btn.dataset.adminTab === name;
      btn.classList.toggle("bg-slate-900", active);
      btn.classList.toggle("text-white", active);
      btn.classList.toggle("bg-white", !active);
      btn.classList.toggle("text-slate-700", !active);
      btn.classList.toggle("border", !active);
      btn.classList.toggle("border-slate-200", !active);
    });
    document.querySelectorAll("[data-admin-panel]").forEach((panel) => {
      panel.classList.toggle("hidden", panel.dataset.adminPanel !== name);
    });
  }

  tabs.forEach((btn) => {
    btn.addEventListener("click", () => activateAdminTab(btn.dataset.adminTab));
  });
})();

// ---------------------------------------------------------------------------
// Admin: User Management
// ---------------------------------------------------------------------------

(function initUserManagement() {
  const form = document.getElementById("createUserForm");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = form.querySelector("button[type=submit]");
      setButtonLoading(btn, true);

      const payload = {
        name: form.cu_name.value.trim(),
        login_id: form.cu_login_id.value.trim(),
        role: form.cu_role.value,
        password: form.cu_password.value,
      };

      try {
        const { ok, data } = await postJSON("/api/admin/users", payload);
        if (ok) {
          alert(data.message || "User created successfully.");
          window.location.reload();
        } else {
          alert(data.message || "Failed to create user.");
        }
      } catch (err) {
        alert("Network error. Please try again.");
      } finally {
        setButtonLoading(btn, false, "Create User");
      }
    });
  }

  document.querySelectorAll("[data-delete-user]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const userId = btn.dataset.deleteUser;
      if (!confirm("Are you sure you want to delete this user?")) return;

      try {
        const res = await fetch(`/api/admin/users/${userId}`, { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
          alert(data.message || "User deleted successfully.");
          window.location.reload();
        } else {
          alert(data.message || "Failed to delete user.");
        }
      } catch (err) {
        alert("Network error. Please try again.");
      }
    });
  });
})();

// ---------------------------------------------------------------------------
// Admin: Approve / Reject single pass
// ---------------------------------------------------------------------------

(function initApproveReject() {
  document.querySelectorAll("[data-approve]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.approve;
      const passType = btn.dataset.passType || "internal";
      btn.disabled = true;
      try {
        const { ok, data } = await postJSON("/api/admin/approve", {
          id: parseInt(id), pass_type: passType,
        });
        if (ok) {
          window.location.reload();
        } else {
          alert(data.message || "Approval failed.");
          btn.disabled = false;
        }
      } catch {
        alert("Network error.");
        btn.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-reject]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.reject;
      const passType = btn.dataset.passType || "internal";
      const comment = prompt("Enter rejection reason (optional):", "") ?? "";
      btn.disabled = true;
      try {
        const { ok, data } = await postJSON("/api/admin/reject", {
          id: parseInt(id), pass_type: passType, comments: comment,
        });
        if (ok) {
          window.location.reload();
        } else {
          alert(data.message || "Rejection failed.");
          btn.disabled = false;
        }
      } catch {
        alert("Network error.");
        btn.disabled = false;
      }
    });
  });
})();

// ---------------------------------------------------------------------------
// Admin: Bulk approve
// ---------------------------------------------------------------------------

(function initBulkApprove() {
  const selectAll = document.getElementById("selectAll");
  const bulkBtn = document.getElementById("bulkApproveBtn");
  if (!bulkBtn) return;

  if (selectAll) {
    selectAll.addEventListener("change", () => {
      document.querySelectorAll(".bulk-check").forEach((cb) => {
        cb.checked = selectAll.checked;
      });
    });
  }

  bulkBtn.addEventListener("click", async () => {
    const checked = [...document.querySelectorAll(".bulk-check:checked")];
    if (!checked.length) { alert("No requests selected."); return; }
    const ids = checked.map((cb) => parseInt(cb.value));
    bulkBtn.disabled = true;
    try {
      const { ok, data } = await postJSON("/api/admin/bulk-approve", {
        ids, pass_type: "internal",
      });
      if (ok) {
        alert(`${data.approved} pass(es) approved.`);
        window.location.reload();
      } else {
        alert(data.message || "Bulk approve failed.");
      }
    } catch {
      alert("Network error.");
    } finally {
      bulkBtn.disabled = false;
    }
  });
})();

// ---------------------------------------------------------------------------
// Admin: Blacklist management
// ---------------------------------------------------------------------------

(function initBlacklist() {
  const form = document.getElementById("blacklistForm");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = form.querySelector("button[type=submit]");
      setButtonLoading(btn, true);
      const payload = {
        national_id: form.bl_national_id.value.trim(),
        name:        form.bl_name.value.trim(),
        reason:      form.bl_reason ? form.bl_reason.value.trim() : "",
      };
      try {
        const { ok, data } = await postJSON("/api/admin/blacklist", payload);
        if (ok) {
          showMessage("blacklistMsg", data.message, "success");
          form.reset();
          setTimeout(() => window.location.reload(), 1500);
        } else {
          showMessage("blacklistMsg", data.message, "error");
        }
      } catch {
        showMessage("blacklistMsg", "Network error.", "error");
      } finally {
        setButtonLoading(btn, false, "Add to Blacklist");
      }
    });
  }

  document.querySelectorAll("[data-remove-blacklist]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm("Remove this individual from the blacklist?")) return;
      const id = btn.dataset.removeBlacklist;
      try {
        const resp = await fetch(`/api/admin/blacklist/${id}`, { method: "DELETE" });
        const data = await resp.json();
        if (resp.ok) window.location.reload();
        else alert(data.message || "Removal failed.");
      } catch {
        alert("Network error.");
      }
    });
  });
})();

// ---------------------------------------------------------------------------
// Guard: Tab switching
// ---------------------------------------------------------------------------

(function initGuardTabs() {
  const tabs = document.querySelectorAll("[data-guard-tab]");
  if (!tabs.length) return;

  function activateGuardTab(name) {
    tabs.forEach((btn) => {
      const active = btn.dataset.guardTab === name;
      btn.className = btn.className
        .replace(/bg-slate-900\s?|text-white\s?|bg-white\s?|text-slate-700\s?|border-slate-200\s?/g, "")
        .trim();
      if (active) {
        btn.classList.add("bg-slate-900", "text-white", "border-slate-900");
      } else {
        btn.classList.add("bg-white", "text-slate-700", "border-slate-200");
      }
    });
    document.querySelectorAll("[data-guard-panel]").forEach((panel) => {
      panel.classList.toggle("hidden", panel.dataset.guardPanel !== name);
    });
  }

  tabs.forEach((btn) => {
    btn.addEventListener("click", () => activateGuardTab(btn.dataset.guardTab));
  });

  activateGuardTab("scan");
})();

// ---------------------------------------------------------------------------
// Guard: Scan direction toggle
// ---------------------------------------------------------------------------

(function initScanDirection() {
  const dirEntry = document.getElementById("dirEntry");
  const dirExit  = document.getElementById("dirExit");
  const hidden   = document.getElementById("scanDirection");
  if (!dirEntry || !dirExit) return;

  function setDirection(dir) {
    hidden.value = dir;
    const isEntry = dir === "ENTRY";
    dirEntry.className = dirEntry.className.replace(/bg-\S+|text-\S+|border-\S+/g, "").trim();
    dirExit.className  = dirExit.className.replace(/bg-\S+|text-\S+|border-\S+/g, "").trim();
    if (isEntry) {
      dirEntry.classList.add("bg-green-600", "text-white", "border-green-600");
      dirExit.classList.add("bg-white", "text-slate-700", "border-slate-300");
    } else {
      dirEntry.classList.add("bg-white", "text-slate-700", "border-slate-300");
      dirExit.classList.add("bg-blue-600", "text-white", "border-blue-600");
    }
  }

  dirEntry.addEventListener("click", () => setDirection("ENTRY"));
  dirExit.addEventListener("click",  () => setDirection("EXIT"));
  setDirection("ENTRY");
})();

// ---------------------------------------------------------------------------
// Guard: Scan result display helper
// ---------------------------------------------------------------------------

function showScanResult(ok, heading, detail, holder) {
  const box = document.getElementById("scanResultBox");
  if (!box) return;
  box.classList.remove("hidden", "border-green-500", "border-red-500", "border-amber-500");
  box.classList.add(ok === true ? "border-green-500" : ok === "warn" ? "border-amber-500" : "border-red-500");
  document.getElementById("scanIcon").textContent    = ok === true ? "✅" : ok === "warn" ? "⚠️" : "❌";
  document.getElementById("scanHeading").textContent = heading;
  document.getElementById("scanDetail").textContent  = detail || "";
  document.getElementById("scanHolder").textContent  = holder || "";
}

async function validateToken(token) {
  const direction = (document.getElementById("scanDirection") || {}).value || "ENTRY";
  try {
    const { ok, data } = await postJSON("/api/guard/scan", { token, scan_type: direction });
    if (ok) {
      showScanResult(true, "ACCESS GRANTED", data.message, data.name || "");
      return true;
    } else {
      showScanResult(false, data.result || "DENIED", data.message, "");
      return false;
    }
  } catch {
    showScanResult(false, "ERROR", "Network error. Please try again.", "");
    return false;
  }
}

// ---------------------------------------------------------------------------
// Guard: Camera QR scanner (html5-qrcode)
// ---------------------------------------------------------------------------

(function initCameraScanner() {
  const startBtn = document.getElementById("startScanBtn");
  const stopBtn  = document.getElementById("stopScanBtn");
  if (!startBtn) return;

  let scanner = null;
  let lastScannedText = "";
  let lastScanTime = 0;

  startBtn.addEventListener("click", () => {
    if (typeof Html5Qrcode === "undefined") {
      alert("QR scanner library not loaded.");
      return;
    }
    scanner = new Html5Qrcode("qr-reader");
    scanner.start(
      { facingMode: "environment" },
      { fps: 10, qrbox: { width: 250, height: 250 } },
      (decodedText) => {
        const now = Date.now();
        // Ignore the exact same token if scanned within the last 3 seconds (3000ms)
        if (decodedText === lastScannedText && now - lastScanTime < 3000) return;

        lastScannedText = decodedText;
        lastScanTime = now;
        validateToken(decodedText.trim()).then((success) => {
          if (success) {
            document.getElementById("stopScanBtn").click();
          }
        });
      },
      () => {}
    ).then(() => {
      startBtn.classList.add("hidden");
      stopBtn.classList.remove("hidden");
    }).catch((err) => alert("Camera error: " + err));
  });

  stopBtn.addEventListener("click", () => {
    if (scanner) {
      scanner.stop().then(() => {
        scanner.clear();
        scanner = null;
        startBtn.classList.remove("hidden");
        stopBtn.classList.add("hidden");
      });
    }
  });
})();

// ---------------------------------------------------------------------------
// Guard: Manual token validation
// ---------------------------------------------------------------------------

(function initManualScan() {
  const btn   = document.getElementById("manualScanBtn");
  const input = document.getElementById("manualToken");
  if (!btn || !input) return;

  async function run() {
    const token = input.value.trim();
    if (!token) return;
    btn.disabled = true;
    btn.textContent = "Checking…";
    await validateToken(token);
    btn.disabled = false;
    btn.textContent = "Validate";
    input.value = "";
  }

  btn.addEventListener("click", run);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
})();

// ---------------------------------------------------------------------------
// Guard: Walk-in registry form
// ---------------------------------------------------------------------------

(function initWalkInForm() {
  const form = document.getElementById("walkInForm");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideMessage("walkInMsg");
    const btn = form.querySelector("button[type=submit]");
    setButtonLoading(btn, true);
    const payload = {
      name:        form.wi_name.value.trim(),
      national_id: form.wi_national_id.value.trim(),
      vehicle_reg: form.wi_vehicle_reg ? form.wi_vehicle_reg.value.trim() : "",
      department:  form.wi_department.value.trim(),
      purpose:     form.wi_purpose.value.trim(),
    };
    try {
      const { ok, data } = await postJSON("/api/guard/walkin", payload);
      if (ok) {
        showMessage("walkInMsg", data.message, "success");
        form.reset();
      } else {
        showMessage("walkInMsg", data.message, data.blacklisted ? "error" : "error");
      }
    } catch {
      showMessage("walkInMsg", "Network error. Please try again.", "error");
    } finally {
      setButtonLoading(btn, false, "✅ Clear & Log Entry");
    }
  });
})();
