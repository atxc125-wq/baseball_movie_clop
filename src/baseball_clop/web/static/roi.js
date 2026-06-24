const ROI_META = {
  pitcher: { label: "投手", color: "red" },
  batter_box: { label: "バッター", color: "limegreen" },
  catcher: { label: "捕手", color: "blue" },
  strike_zone: { label: "ストライクゾーン", color: "darkcyan" },
  base_first: { label: "1B牽制", color: "magenta" },
  base_third: { label: "3B牽制", color: "orange" },
};

const MIN_SIZE = 0.02;

const wrap = document.getElementById("frame-wrap");
const boxesLayer = document.getElementById("boxes");
const img = document.getElementById("frame-img");
const statusEl = document.getElementById("status");

let rois = window.INITIAL_ROIS;
let drag = null; // {name, corner: "nw"|"ne"|"sw"|"se"|null, startClientX, startClientY, orig}

function clamp01(v) {
  return Math.min(1, Math.max(0, v));
}

function pctStyle(roi) {
  return {
    left: roi.x0 * 100 + "%",
    top: roi.y0 * 100 + "%",
    width: (roi.x1 - roi.x0) * 100 + "%",
    height: (roi.y1 - roi.y0) * 100 + "%",
  };
}

function render() {
  boxesLayer.innerHTML = "";
  for (const name of Object.keys(ROI_META)) {
    const meta = ROI_META[name];
    const roi = rois[name];

    const box = document.createElement("div");
    box.className = "roi-box";
    box.dataset.name = name;
    box.style.borderColor = meta.color;
    Object.assign(box.style, pctStyle(roi));

    const label = document.createElement("span");
    label.className = "roi-label";
    label.textContent = meta.label;
    label.style.background = meta.color;
    box.appendChild(label);

    for (const corner of ["nw", "ne", "sw", "se"]) {
      const handle = document.createElement("div");
      handle.className = "roi-handle roi-handle-" + corner;
      handle.dataset.corner = corner;
      box.appendChild(handle);
    }

    boxesLayer.appendChild(box);
  }
}

boxesLayer.addEventListener("mousedown", (e) => {
  const box = e.target.closest(".roi-box");
  if (!box) return;
  const handle = e.target.closest(".roi-handle");
  drag = {
    name: box.dataset.name,
    corner: handle ? handle.dataset.corner : null,
    startClientX: e.clientX,
    startClientY: e.clientY,
    orig: { ...rois[box.dataset.name] },
  };
  e.preventDefault();
});

window.addEventListener("mousemove", (e) => {
  if (!drag) return;
  const rect = wrap.getBoundingClientRect();
  const dx = (e.clientX - drag.startClientX) / rect.width;
  const dy = (e.clientY - drag.startClientY) / rect.height;
  const roi = { ...drag.orig };

  if (!drag.corner) {
    const w = roi.x1 - roi.x0;
    const h = roi.y1 - roi.y0;
    const x0 = Math.min(clamp01(roi.x0 + dx), 1 - w);
    const y0 = Math.min(clamp01(roi.y0 + dy), 1 - h);
    roi.x0 = x0;
    roi.x1 = x0 + w;
    roi.y0 = y0;
    roi.y1 = y0 + h;
  } else {
    if (drag.corner.includes("w")) roi.x0 = clamp01(roi.x0 + dx);
    if (drag.corner.includes("e")) roi.x1 = clamp01(roi.x1 + dx);
    if (drag.corner.includes("n")) roi.y0 = clamp01(roi.y0 + dy);
    if (drag.corner.includes("s")) roi.y1 = clamp01(roi.y1 + dy);

    if (roi.x1 - roi.x0 < MIN_SIZE) {
      if (drag.corner.includes("w")) roi.x0 = roi.x1 - MIN_SIZE;
      else roi.x1 = roi.x0 + MIN_SIZE;
    }
    if (roi.y1 - roi.y0 < MIN_SIZE) {
      if (drag.corner.includes("n")) roi.y0 = roi.y1 - MIN_SIZE;
      else roi.y1 = roi.y0 + MIN_SIZE;
    }
  }

  rois[drag.name] = roi;
  render();
});

window.addEventListener("mouseup", () => {
  drag = null;
});

document.getElementById("reload-frame").addEventListener("click", () => {
  const t = document.getElementById("t-sec").value;
  img.src = "/api/frame.png?t_sec=" + encodeURIComponent(t) + "&_=" + Date.now();
});

document.getElementById("save-btn").addEventListener("click", async () => {
  const res = await fetch("/api/rois", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(rois),
  });
  if (res.ok) {
    statusEl.textContent = "保存しました。";
    statusEl.style.color = "green";
  } else {
    statusEl.textContent = "保存に失敗しました。";
    statusEl.style.color = "#c00";
  }
});

render();

const detectBtn = document.getElementById("detect-btn");
const detectStatusEl = document.getElementById("detect-status");
let detectPollTimer = null;

function renderDetectStatus(data) {
  if (data.state === "running") {
    detectStatusEl.textContent = data.message || "実行中...";
    detectStatusEl.style.color = "#555";
  } else if (data.state === "done") {
    detectStatusEl.textContent =
      `検出完了: 投球${data.pitch_count}件・牽制候補${data.pickoff_count}件` +
      `(${data.timeline_path})。${data.message}`;
    detectStatusEl.style.color = "green";
  } else if (data.state === "error") {
    detectStatusEl.textContent = "エラー: " + data.message;
    detectStatusEl.style.color = "#c00";
  }
}

function pollDetectStatus() {
  fetch("/api/detect-status")
    .then((res) => res.json())
    .then((data) => {
      renderDetectStatus(data);
      if (data.state !== "running") {
        clearInterval(detectPollTimer);
        detectPollTimer = null;
        detectBtn.disabled = false;
      }
    });
}

detectBtn.addEventListener("click", async () => {
  detectBtn.disabled = true;
  detectStatusEl.textContent = "検出を開始しています...";
  detectStatusEl.style.color = "#555";

  const res = await fetch("/api/detect", { method: "POST" });
  const data = await res.json();
  if (!res.ok) {
    detectStatusEl.textContent = data.error || "検出を開始できませんでした。";
    detectStatusEl.style.color = "#c00";
    detectBtn.disabled = false;
    return;
  }
  detectPollTimer = setInterval(pollDetectStatus, 2000);
});

// 画面を開き直した場合に、前回/実行中の検出状態を復元する。
fetch("/api/detect-status")
  .then((res) => res.json())
  .then((data) => {
    if (data.state === "idle") return;
    renderDetectStatus(data);
    if (data.state === "running") {
      detectBtn.disabled = true;
      detectPollTimer = setInterval(pollDetectStatus, 2000);
    }
  });
