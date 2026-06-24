import pytest

from baseball_clop import roi_store
from baseball_clop.cli import _build_config
from baseball_clop.config import ROI, MainCameraROIs


def _custom_rois():
    return MainCameraROIs(
        pitcher=ROI(0.1, 0.1, 0.2, 0.2),
        batter_box=ROI(0.3, 0.3, 0.4, 0.4),
        catcher=ROI(0.5, 0.5, 0.6, 0.6),
        strike_zone=ROI(0.55, 0.55, 0.58, 0.58),
        base_first=ROI(0.7, 0.7, 0.8, 0.8),
        base_third=ROI(0.0, 0.0, 0.1, 0.1),
    )


def test_build_config_without_rois_uses_default():
    config = _build_config(None)
    assert config.detection.main_rois == MainCameraROIs()


def test_build_config_loads_saved_rois(tmp_path):
    rois_path = tmp_path / "rois.json"
    custom = _custom_rois()
    roi_store.save(custom, rois_path)

    config = _build_config(str(rois_path))

    assert config.detection.main_rois == custom


def test_build_config_missing_rois_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        _build_config(str(tmp_path / "missing.json"))
