"use strict";
const statusBox = document.getElementById("status");
const image = document.getElementById("screen");
let credentials;
try {
  const fragment = new URLSearchParams(location.hash.slice(1));
  if (fragment.get("session") && fragment.get("token")) {
    credentials = {id: fragment.get("session"), token: fragment.get("token")};
    sessionStorage.setItem("browserSession", JSON.stringify(credentials));
    history.replaceState(null, "", "/");
  } else {
    credentials = JSON.parse(sessionStorage.getItem("browserSession") || "null");
  }
} catch (_) { credentials = null; }
let stopped = false, busy = false, oldImage = null, down = null;
const terminal = new Set(["ready", "error", "expired", "stopped"]);
async function api(suffix, payload) {
  if (!credentials) throw new Error("Открой ссылку из Telegram-бота.");
  const response = await fetch("/v1/sessions/" + encodeURIComponent(credentials.id) + suffix, {
    method: payload === undefined ? "GET" : "POST",
    headers: {Authorization: "Bearer " + credentials.token, "Content-Type": "application/json"},
    body: payload === undefined ? undefined : JSON.stringify(payload), cache: "no-store"
  });
  if (!response.ok) {
    if ([401, 404, 410].includes(response.status)) stopped = true;
    throw new Error("Сессия недоступна (HTTP " + response.status + "). Вернись в бот.");
  }
  return response;
}
async function refresh() {
  if (stopped || busy || document.hidden || !credentials) return;
  busy = true;
  try {
    const state = await (await api("")).json();
    statusBox.textContent = state.message + " Осталось: " + state.expires_in + " с.";
    if (terminal.has(state.phase)) {
      stopped = true;
      image.removeAttribute("src");
      return;
    }
    if (state.phase !== "opening") {
      try {
        const response = await api("/screen");
        const next = URL.createObjectURL(await response.blob());
        image.src = next;
        if (oldImage) URL.revokeObjectURL(oldImage);
        oldImage = next;
      } catch (error) {
        if (stopped) throw error;
        // A frame can disappear during the switch to a clean login session.
      }
    }
  } catch (error) { statusBox.textContent = error.message; }
  finally { busy = false; }
}
async function act(payload) {
  try {
    const state = await (await api("/action", payload)).json();
    statusBox.textContent = state.message;
    if (terminal.has(state.phase)) stopped = true;
    await refresh();
  } catch (error) { statusBox.textContent = error.message; }
}
function coords(event) {
  const box = image.getBoundingClientRect();
  return {x: Math.max(0, Math.min(959, (event.clientX - box.left) * 960 / box.width)),
          y: Math.max(0, Math.min(719, (event.clientY - box.top) * 720 / box.height))};
}
image.addEventListener("pointerdown", event => {
  if (!image.src || stopped) return;
  down = coords(event);
  image.setPointerCapture(event.pointerId);
  event.preventDefault();
});
image.addEventListener("pointerup", event => {
  if (!down) return;
  const end = coords(event), start = down;
  down = null;
  const dragged = Math.hypot(end.x - start.x, end.y - start.y) > 6;
  act(dragged ? {kind: "drag", x: start.x, y: start.y, x2: end.x, y2: end.y} : {kind: "click", ...end});
});
image.addEventListener("pointercancel", () => { down = null; });
document.getElementById("resume").onclick = () => act({kind: "resume"});
document.getElementById("stop").onclick = () => act({kind: "stop"});
document.querySelectorAll("[data-key]").forEach(button => button.onclick = () => act({kind: "key", key: button.dataset.key}));
document.querySelectorAll("[data-scroll]").forEach(button => button.onclick = () => act({kind: "scroll", dy: Number(button.dataset.scroll)}));
document.getElementById("typing").onsubmit = async event => {
  event.preventDefault();
  const field = document.getElementById("text");
  await act({kind: "text", text: field.value});
  field.value = "";
};
if (credentials) { refresh(); setInterval(refresh, 1200); }
window.addEventListener("pagehide", () => { if (oldImage) URL.revokeObjectURL(oldImage); });
