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

  let mainTime = mainVideo.currentTime;
  let wideTime = mainTime + offsetSec;

  if (wideTime < 0) {
    // ワイド映像がまだ始まっていない位置だったので、ワイドの開始位置(0秒)に
    // 合わせてメイン側を自動で進める(逆にワイド側を止めても見比べができないため)。
    mainTime = Math.max(0, -offsetSec);
    wideTime = 0;
    mainVideo.currentTime = mainTime;
    statusEl.textContent =
      `この位置はワイド映像の録画開始前のため、メイン側を${mainTime.toFixed(1)}秒まで自動的に進めました。`;
  } else {
    statusEl.textContent = "";
  }

  wideVideo.currentTime = wideTime;

  mainVideo.play();
  wideVideo.play();
});
