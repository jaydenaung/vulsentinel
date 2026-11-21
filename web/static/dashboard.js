// Poll check progress while a check runs; reload when it finishes.
function pollCheck() {
  fetch("/api/check/status", { credentials: "same-origin" })
    .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
    .then((data) => {
      if (!data.is_running) {
        location.reload();
        return;
      }
      const el = document.getElementById("checkProgress");
      if (el && data.total > 0) {
        el.textContent = `(${data.progress}/${data.total}: ${data.current_product || ""})`;
      }
      setTimeout(pollCheck, 3000);
    })
    .catch(() => setTimeout(pollCheck, 10000));
}
setTimeout(pollCheck, 3000);
