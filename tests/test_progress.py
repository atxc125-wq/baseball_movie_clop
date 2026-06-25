from baseball_clop.progress import ConsoleProgress


def test_update_prints_percentage(capsys):
    progress = ConsoleProgress("テスト", total=100.0, min_interval_sec=0.0)
    progress.update(50)
    out = capsys.readouterr().err
    assert "50.0%" in out


def test_update_throttles_by_interval(capsys):
    progress = ConsoleProgress("テスト", total=100.0, min_interval_sec=1000.0)
    progress.update(10)
    progress.update(20)
    out = capsys.readouterr().err
    assert out.count("%") == 1


def test_finish_prints_100_percent_and_newline(capsys):
    progress = ConsoleProgress("テスト", total=4.0, min_interval_sec=1000.0)
    progress.update(1)
    progress.finish()
    out = capsys.readouterr().err
    assert "100.0%" in out
    assert out.endswith("\n")


def test_zero_total_does_not_divide_by_zero(capsys):
    progress = ConsoleProgress("テスト", total=0.0, min_interval_sec=0.0)
    progress.update(0)
    out = capsys.readouterr().err
    assert "0.0%" in out
