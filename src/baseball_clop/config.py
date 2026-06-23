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
    """main(マウンド-ホーム)カメラ上のROI。

    デフォルト値は実サンプル映像(data/samples/062201_*.mp4)を目視・モーション解析で
    実測したもの: そのカメラは「マウンド-ホームを縦に収める」想定とは異なり、三塁側
    付近から内野全体を横に収める広角寄りのアングルで、捕手・打者は画面右寄り、投手は
    画面中央やや左に小さく写る。カメラ位置やズーム倍率が変わる場合は要再調整。"""

    # 投手のシルエットだけにできるだけ絞ったタイトな矩形。広めに取ると周囲の地面・
    # 観客・他の野手の動きが平均に混ざり、ワインドアップのSNRが大きく落ちる。
    pitcher: ROI = field(default_factory=lambda: ROI(0.26, 0.45, 0.40, 0.68))
    batter_box: ROI = field(default_factory=lambda: ROI(0.58, 0.30, 0.80, 0.90))
    catcher: ROI = field(default_factory=lambda: ROI(0.76, 0.55, 0.93, 0.95))
    # ストライクゾーン推定用(捕手付近、打者の腰〜膝の高さを想定した粗い矩形)
    strike_zone: ROI = field(default_factory=lambda: ROI(0.68, 0.58, 0.80, 0.78))
    # 牽制の送球先候補(投手の右=1塁方向、投手の左=3塁方向の内野上)。
    # サンプル映像に牽制シーンが無いため低確度の推定値。実際の牽制映像で要検証。
    base_first: ROI = field(default_factory=lambda: ROI(0.36, 0.35, 0.62, 0.58))
    base_third: ROI = field(default_factory=lambda: ROI(0.04, 0.45, 0.26, 0.70))


@dataclass
class DetectionConfig:
    # 解析用に縮小する際の幅(px)。4K映像でも処理速度を確保するため。
    # 実サンプル映像は1076px幅(4Kではない)なので、それより縮小しないよう
    # 高めに設定している(iter_frames側はこれより狭い映像を拡大はしない)。
    analysis_width: int = 1080

    # --- 投球動作検出 ---
    # 以下のしきい値は実サンプル映像(投手がフレーム中央やや左に小さく写る広角アングル)
    # で実測した値: 静止時の平均輝度差分は0.2〜0.4程度、実際のワインドアップでの
    # ピークは1〜2.5程度、一方でカメラ近くを人が横切る/打球処理後の乱戦などでは
    # 10〜25程度まで跳ね上がる。この差が大きいため、上限(max_rise)で
    # 「投手にしては動きすぎ」なイベントを別物として弾く。
    pre_roll_sec: float = 1.0  # セット/ワインドアップ開始の何秒前から切り出すか
    pitcher_motion_threshold: float = 0.45  # 静止とみなす平均輝度差分の上限
    pitcher_motion_min_rise: float = 0.85  # これを超えたら「動き出した」と判定
    pitcher_motion_max_rise: float = 6.0  # これを超える急上昇は人の横切り等とみなし除外
    pitcher_still_min_sec: float = 0.5  # 静止期間としてみなす最小長さ
    # rise_threshold超えが単発1フレームだけのノイズ(圧縮アーティファクト等)を「動き出し」
    # から除外するため、最低でも連続してこの数のフレームを超え続けることを要求する。実測では
    # セットへの移行や捕手とのボールやり取りなど本物の投球ではない動きが単発1フレームの
    # スパイクとして紛れ込みやすく、本物のワインドアップ/リリースは複数フレーム連続して
    # 閾値を超え続ける。
    pitcher_motion_min_consecutive_rise: int = 2
    pickoff_max_sec_after_motion: float = 1.2  # 動作開始から牽制/投球が完了するまでの探索窓

    # --- スイング/打球判定 ---
    swing_reaction_window_sec: tuple[float, float] = (0.15, 1.0)
    # 実測(実映像で確認済みの見逃し1球・打球1球): 見逃し時のバッターボックスROIピークは
    # 1.3程度、実際のスイング+打球時のピークは2.7程度。中間の2.0をしきい値とする。
    swing_motion_threshold: float = 2.0
    pitch_flight_max_sec: float = 1.2  # リリースから捕手到達までの最大探索時間
    # 見逃し/空振りクリップの終了点: 捕球からこの秒数後まで(捕球の瞬間で即終了すると
    # 不自然なため、捕球後の余韻を含める)。
    catch_post_roll_sec: float = 3.0
    # クリップ開始点の基準: 見逃し/空振りは捕球、打球は打音(コンタクト)の瞬間を
    # 基準点(0)とし、その何秒前から切り出すか。motion_start基準だとセット〜
    # ワインドアップの一部しか映らないことがあるため、結果が分かる瞬間側を基準に
    # する方が安定して投球モーション〜結果を収められる。
    pre_roll_anchor_sec: float = 5.0

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
