// Confirm dialogs for destructive forms. Replaces inline onsubmit handlers (CSP-safe).
document.addEventListener("submit", (event) => {
  const form = event.target;
  const message = form instanceof HTMLFormElement ? form.dataset.confirm : undefined;
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});
