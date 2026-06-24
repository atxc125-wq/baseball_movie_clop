document.getElementById("setup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const body = {
    main_path: form.main_path.value,
    wide_path: form.wide_path.value,
    out_dir: form.out_dir.value,
    wide_offset_sec: form.wide_offset_sec.value,
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

document.getElementById("sync-audio-btn").addEventListener("click", async () => {
  const form = document.getElementById("setup-form");
  const resultEl = document.getElementById("sync-audio-result");
  resultEl.textContent = "解析中...";

  const res = await fetch("/api/sync-audio", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      main_path: form.main_path.value,
      wide_path: form.wide_path.value,
    }),
  });
  const data = await res.json();
  if (!res.ok) {
    resultEl.textContent = data.error || "検出に失敗しました";
    return;
  }
  form.wide_offset_sec.value = data.offset_sec.toFixed(3);
  resultEl.textContent =
    `検出: ${data.offset_sec.toFixed(3)}秒 (信頼度 ${(data.confidence * 100).toFixed(0)}% ` +
    `— 必ず映像を見て確認してください)`;
});
