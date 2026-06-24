from baseball_clop import roi_store
from baseball_clop.config import ROI, MainCameraROIs


def _rois():
    return MainCameraROIs(
        pitcher=ROI(0.3, 0.05, 0.7, 0.35),
        batter_box=ROI(0.15, 0.55, 0.85, 0.85),
        catcher=ROI(0.35, 0.75, 0.65, 1.0),
        strike_zone=ROI(0.40, 0.62, 0.60, 0.80),
        base_first=ROI(0.75, 0.1, 1.0, 0.6),
        base_third=ROI(0.0, 0.1, 0.25, 0.6),
    )


def test_load_missing_file_returns_none(tmp_path):
    assert roi_store.load(tmp_path / "missing.json") is None


def test_save_then_load_roundtrips(tmp_path):
    path = tmp_path / "rois.json"
    rois = _rois()

    roi_store.save(rois, path)
    loaded = roi_store.load(path)

    assert loaded == rois
