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

  const maxOffsetSec = parseFloat(document.getElementById("max-offset-sec").value) || 20;

  const res = await fetch("/api/sync-audio", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      main_path: form.main_path.value,
      wide_path: form.wide_path.value,
      max_offset_sec: maxOffsetSec,
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

document.getElementById("load-preview-btn").addEventListener("click", async () => {
  const form = document.getElementById("setup-form");
  const statusEl = document.getElementById("preview-status");
  statusEl.textContent = "読み込み中...";

  const res = await fetch("/api/preview-paths", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      main_path: form.main_path.value,
      wide_path: form.wide_path.value,
    }),
  });
  const data = await res.json();
  if (!res.ok) {
    statusEl.textContent = data.error || "読み込みに失敗しました";
    return;
  }

  const cacheBust = `?t=${Date.now()}`;
  document.getElementById("preview-main").src = "/api/video/main" + cacheBust;
  document.getElementById("preview-wide").src = "/api/video/wide" + cacheBust;
  statusEl.textContent = "読み込み完了。メイン映像をシークしてから「この位置から同時再生」を押してください。";
});

document.getElementById("sync-play-btn").addEventListener("click", () => {
  const form = document.getElementById("setup-form");
  const mainVideo = document.getElementById("preview-main");
  const wideVideo = document.getElementById("preview-wide");
  const statusEl = document.getElementById("preview-status");
  const offsetSec = parseFloat(form.wide_offset_sec.value) || 0;

  const mainTime = mainVideo.currentTime;
  const wideTime = mainTime + offsetSec;

  wideVideo.currentTime = Math.max(0, wideTime);
  statusEl.textContent =
    wideTime < 0
      ? "この位置より前はワイド映像が始まっていないため、ワイド側は0秒から再生します。"
      : "";

  mainVideo.play();
  wideVideo.play();
});
