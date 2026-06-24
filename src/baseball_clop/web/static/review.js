const JUDGEMENT_MAP = {
  take_ball: { outcome: "take", pitch_call: "ball" },
  take_strike: { outcome: "take", pitch_call: "strike" },
  swing_miss: { outcome: "swing_miss", pitch_call: "strike" },
  foul: { outcome: "foul", pitch_call: "foul" },
  in_play: { outcome: "in_play", pitch_call: "in_play" },
  unknown: { outcome: "unknown", pitch_call: "unknown" },
};

const NON_INPLAY_RESULTS = new Set(["none", "walk", "strikeout"]);

let pitches = window.INITIAL_PITCHES || [];
let currentPitch = null;

const player = document.getElementById("player");
const saveStatusEl = document.getElementById("save-status");

function fieldsToJudgement(outcome, pitchCall) {
  for (const [key, val] of Object.entries(JUDGEMENT_MAP)) {
    if (val.outcome === outcome && val.pitch_call === pitchCall) return key;
  }
  return "unknown";
}

function fmtCount(c) {
  return `${c.balls}-${c.strikes}-${c.outs}`;
}

function fmtRunners(r) {
  return `1B:${r["1B"] ? "○" : "-"} 2B:${r["2B"] ? "○" : "-"} 3B:${r["3B"] ? "○" : "-"}`;
}

function toggleInplayPanel(show) {
  document.getElementById("inplay-panel").style.display = show ? "" : "none";
}

function renderSidebar() {
  const list = document.getElementById("pitch-list");
  list.innerHTML = "";
  for (const p of pitches) {
    const li = document.createElement("li");
    li.dataset.id = p.id;
    const half = p.half === "top" ? "表" : "裏";
    const mark = p.needs_review ? " ⚠" : "";
    li.textContent = `${p.id} ${p.inning}回${half} ${p.outcome}/${p.pitch_call}${mark}`;
    li.addEventListener("click", () => loadPitchById(p.id));
    list.appendChild(li);
  }
  highlightSidebar(currentPitch ? currentPitch.id : null);
}

function highlightSidebar(id) {
  document.querySelectorAll("#pitch-list li").forEach((li) => {
    li.classList.toggle("active", li.dataset.id === id);
  });
}

function populateForm(pitch) {
  currentPitch = pitch;

  const halfLabel = pitch.half === "top" ? "表" : "裏";
  document.getElementById("current-pitch-label").textContent = `投球 ${pitch.id}(${pitch.inning}回${halfLabel})`;

  document.getElementById("clip-start").value = pitch.clip_start_sec.toFixed(2);
  document.getElementById("clip-end").value = pitch.clip_end_sec.toFixed(2);

  const judgement = fieldsToJudgement(pitch.outcome, pitch.pitch_call);
  document.getElementById("judgement").value = judgement;
  toggleInplayPanel(judgement === "in_play");

  const resultValue = NON_INPLAY_RESULTS.has(pitch.in_play.result) ? "unknown" : pitch.in_play.result;
  document.getElementById("inplay-result").value = resultValue;
  document.getElementById("outs-on-play").value = pitch.in_play.outs_on_play || 0;

  const resolved = pitch.in_play.resolved_runners;
  const overrideOn = !!resolved;
  document.getElementById("runners-override").checked = overrideOn;
  const source = overrideOn ? resolved : pitch.runners_after;
  document.getElementById("runner-1b").checked = !!source["1B"];
  document.getElementById("runner-2b").checked = !!source["2B"];
  document.getElementById("runner-3b").checked = !!source["3B"];

  document.getElementById("inning").value = pitch.inning;
  document.getElementById("half").value = pitch.half;

  document.getElementById("count-before").textContent = fmtCount(pitch.count_before);
  document.getElementById("count-after").textContent = fmtCount(pitch.count_after);
  document.getElementById("runners-before").textContent = fmtRunners(pitch.runners_before);
  document.getElementById("runners-after").textContent = fmtRunners(pitch.runners_after);

  document.getElementById("needs-review").checked = pitch.needs_review;
  document.getElementById("notes").value = pitch.notes || "";

  saveStatusEl.textContent = "";
  highlightSidebar(pitch.id);
}

async function loadPitchById(id) {
  const res = await fetch(`/api/pitches/${encodeURIComponent(id)}`);
  if (!res.ok) {
    saveStatusEl.textContent = "投球の取得に失敗しました。";
    saveStatusEl.style.color = "#c00";
    return null;
  }
  const pitch = await res.json();
  populateForm(pitch);
  player.pause();
  player.playbackRate = 1.0;
  player.currentTime = pitch.clip_start_sec;
  return pitch;
}

function collectFormData() {
  const judgement = document.getElementById("judgement").value;
  const fields = JUDGEMENT_MAP[judgement];
  const isInPlay = judgement === "in_play";
  const overrideOn = document.getElementById("runners-override").checked;
  const resolvedRunners =
    isInPlay && overrideOn
      ? {
          "1B": document.getElementById("runner-1b").checked,
          "2B": document.getElementById("runner-2b").checked,
          "3B": document.getElementById("runner-3b").checked,
        }
      : null;

  return {
    clip_start_sec: parseFloat(document.getElementById("clip-start").value),
    clip_end_sec: parseFloat(document.getElementById("clip-end").value),
    outcome: fields.outcome,
    pitch_call: fields.pitch_call,
    in_play: {
      result: isInPlay ? document.getElementById("inplay-result").value : "none",
      outs_on_play: isInPlay ? parseInt(document.getElementById("outs-on-play").value, 10) || 0 : 0,
      resolved_runners: resolvedRunners,
    },
    inning: parseInt(document.getElementById("inning").value, 10),
    half: document.getElementById("half").value,
    needs_review: document.getElementById("needs-review").checked,
    notes: document.getElementById("notes").value,
    apply_inning_half_forward: document.getElementById("apply-forward").checked,
  };
}

async function refreshPitchList() {
  const res = await fetch("/api/pitches");
  if (res.ok) {
    pitches = await res.json();
    renderSidebar();
  }
}

function findNextPitch(id) {
  const idx = pitches.findIndex((p) => p.id === id);
  if (idx === -1 || idx + 1 >= pitches.length) return null;
  return pitches[idx + 1];
}

async function savePitch() {
  const body = collectFormData();
  if (body.clip_start_sec >= body.clip_end_sec) {
    saveStatusEl.textContent = "開始位置は終了位置より前である必要があります。";
    saveStatusEl.style.color = "#c00";
    return null;
  }

  const res = await fetch(`/api/pitches/${encodeURIComponent(currentPitch.id)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    saveStatusEl.textContent = "保存に失敗しました: " + (data.error || "");
    saveStatusEl.style.color = "#c00";
    return null;
  }

  await refreshPitchList();

  let msg = "保存しました。";
  if (data.forward_filled_count > 0) {
    msg += ` 以降の${data.forward_filled_count}件にも回/表裏を適用しました。`;
  }
  saveStatusEl.textContent = msg;
  saveStatusEl.style.color = "green";
  return data;
}

function startGapScan(fromSec, nextSummary) {
  player.pause();
  player.currentTime = fromSec;
  player.playbackRate = 2.0;

  function onTimeUpdate() {
    if (player.currentTime >= nextSummary.clip_start_sec || player.currentTime > nextSummary.clip_end_sec) {
      player.removeEventListener("timeupdate", onTimeUpdate);
      player.playbackRate = 1.0;
      loadPitchById(nextSummary.id);
    }
  }
  player.addEventListener("timeupdate", onTimeUpdate);
  player.play();
}

document.getElementById("judgement").addEventListener("change", (e) => {
  toggleInplayPanel(e.target.value === "in_play");
});

document.getElementById("runners-override").addEventListener("change", (e) => {
  if (e.target.checked && currentPitch) {
    const r = currentPitch.runners_after;
    document.getElementById("runner-1b").checked = r["1B"];
    document.getElementById("runner-2b").checked = r["2B"];
    document.getElementById("runner-3b").checked = r["3B"];
  }
});

document.querySelectorAll("button[data-trim]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const targetId = btn.dataset.trim === "start" ? "clip-start" : "clip-end";
    const delta = parseFloat(btn.dataset.delta);
    const el = document.getElementById(targetId);
    el.value = (parseFloat(el.value || "0") + delta).toFixed(2);
  });
});

document.getElementById("set-start-btn").addEventListener("click", () => {
  document.getElementById("clip-start").value = player.currentTime.toFixed(2);
});

document.getElementById("set-end-btn").addEventListener("click", () => {
  document.getElementById("clip-end").value = player.currentTime.toFixed(2);
});

document.getElementById("save-stay-btn").addEventListener("click", async () => {
  const data = await savePitch();
  if (data) populateForm(data);
});

document.getElementById("save-next-btn").addEventListener("click", async () => {
  const data = await savePitch();
  if (!data) return;
  const next = findNextPitch(data.id);
  if (!next) {
    saveStatusEl.textContent += " (これが最後の投球です)";
    return;
  }
  startGapScan(data.clip_end_sec, next);
});

document.getElementById("skip-gap-btn").addEventListener("click", () => {
  if (!currentPitch) return;
  const next = findNextPitch(currentPitch.id);
  if (!next) {
    saveStatusEl.textContent = "これが最後の投球です。";
    return;
  }
  loadPitchById(next.id);
});

renderSidebar();
if (pitches.length > 0) {
  loadPitchById(pitches[0].id);
}
