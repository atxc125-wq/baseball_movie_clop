document.getElementById("setup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const body = {
    main_path: form.main_path.value,
    wide_path: form.wide_path.value,
    out_dir: form.out_dir.value,
  };
  const res = await fetch("/api/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    document.getElementById("error").textContent = data.error || "エラーが発生しました";
    return;
  }
  window.location.href = "/roi";
});
