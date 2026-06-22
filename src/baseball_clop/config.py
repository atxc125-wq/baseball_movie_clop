"""パイプライン全体の設定値。

ROI(関心領域)は解像度に依存しないよう、フレーム幅・高さに対する比率 (0.0〜1.0) で
指定する。main(マウンド-ホーム4K)と wide(広角HD)は解像度が異なるため、画素座標では
なく比率で統一して扱う。

実際の試合映像でチューニングする際は、まずこのファイルの値を調整すること。
検出ロジック自体を差し替えたい場合は detection/ 以下の各 *Detector クラスを
継承して config に渡す実装を切り替える。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ROI:
    """フレーム幅・高さに対する比率で表す矩形領域 (x0, y0, x1, y1)。"""

    x0: float
    y0: float
    x1: float
    y1: float

    def to_pixels(self, width: int, height: int) -> tuple[int, int, int, int]:
        return (
            int(self.x0 * width),
            int(self.y0 * height),
            int(self.x1 * width),
            int(self.y1 * height),
        )


@dataclass
class MainCameraROIs:
    """main(マウンド-ホーム)カメラ上のROI。デフォルトはカメラがマウンド-ホームを
    縦に収めるアングルを想定したおおよその値。実映像に合わせて要調整。"""

    pitcher: ROI = field(default_factory=lambda: ROI(0.30, 0.05, 0.70, 0.45))
    batter_box: ROI = field(default_factory=lambda: ROI(0.15, 0.55, 0.85, 0.85))
    catcher: ROI = field(default_factory=lambda: ROI(0.30, 0.75, 0.70, 0.98))
    # ストライクゾーン推定用(捕手付近、打者の腰〜膝の高さを想定した粗い矩形)
    strike_zone: ROI = field(default_factory=lambda: ROI(0.40, 0.62, 0.60, 0.80))
    # 牽制の送球先候補 (1塁/3塁方向は画面左右、2塁方向は中央上)
    base_first: ROI = field(default_factory=lambda: ROI(0.70, 0.20, 1.00, 0.55))
    base_third: ROI = field(default_factory=lambda: ROI(0.00, 0.20, 0.30, 0.55))


@dataclass
class DetectionConfig:
    # 解析用に縮小する際の幅(px)。4K映像でも処理速度を確保するため。
    analysis_width: int = 480

    # --- 投球動作検出 ---
    pre_roll_sec: float = 1.0  # セット/ワインドアップ開始の何秒前から切り出すか
    pitcher_motion_threshold: float = 6.0  # 静止とみなす平均輝度差分の上限
    pitcher_motion_min_rise: float = 14.0  # これを超えたら「動き出した」と判定
    pitcher_still_min_sec: float = 0.5  # 静止期間としてみなす最小長さ
    pickoff_max_sec_after_motion: float = 1.2  # 動作開始から牽制/投球が完了するまでの探索窓

    # --- スイング/打球判定 ---
    swing_reaction_window_sec: tuple[float, float] = (0.15, 1.0)
    swing_motion_threshold: float = 16.0
    pitch_flight_max_sec: float = 1.2  # リリースから捕手到達までの最大探索時間
    catch_buffer_sec: float = 0.3  # 捕手到達からクリップ終了までの余白

    # --- 打球処理(プレー終了)判定 ---
    play_end_still_threshold: float = 5.0
    play_end_min_still_sec: float = 1.5
    play_end_max_search_sec: float = 25.0

    # --- カメラ選択 ---
    camera_switch_radius_frac: float = 0.35  # ホームベースからこの比率を超えて
    # ボールが離れたら広角(wide)に切り替える

    main_rois: MainCameraROIs = field(default_factory=MainCameraROIs)


@dataclass
class ClipConfig:
    pre_roll_pad_sec: float = 0.0  # クリップ開始のさらに前に余白を足す場合
    post_roll_pad_sec: float = 0.0
    output_width: int = 1920
    output_height: int = 1080
    output_fps: float = 30.0
    include_audio: bool = False
    video_codec: str = "libx264"
    crf: int = 18
    preset: str = "veryfast"
    accurate_seek: bool = True  # True: 再エンコードしてフレーム精度を優先


@dataclass
class PipelineConfig:
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    clip: ClipConfig = field(default_factory=ClipConfig)
