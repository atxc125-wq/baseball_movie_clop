import numpy as np

from baseball_clop.config import ROI, MainCameraROIs
from baseball_clop.roi_preview import draw_rois


def _rois():
    return MainCameraROIs(
        pitcher=ROI(0.3, 0.05, 0.7, 0.35),
        batter_box=ROI(0.15, 0.55, 0.85, 0.85),
        catcher=ROI(0.35, 0.75, 0.65, 1.0),
        strike_zone=ROI(0.40, 0.62, 0.60, 0.80),
        base_first=ROI(0.75, 0.1, 1.0, 0.6),
        base_third=ROI(0.0, 0.1, 0.25, 0.6),
    )


def test_draw_rois_does_not_mutate_input_and_draws_something():
    frame = np.zeros((240, 320, 3), dtype=np.uint8)
    original = frame.copy()

    annotated = draw_rois(frame, _rois())

    assert annotated.shape == frame.shape
    assert np.array_equal(frame, original)
    assert not np.array_equal(annotated, frame)


def test_draw_rois_pitcher_box_corner_is_colored():
    frame = np.zeros((240, 320, 3), dtype=np.uint8)
    rois = _rois()

    annotated = draw_rois(frame, rois)

    x0, y0, _, _ = rois.pitcher.to_pixels(320, 240)
    assert annotated[y0, x0].any()
