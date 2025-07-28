import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # noqa: E402

from dinner_app.recipes import possible_dinners  # noqa: E402


def test_possible_dinners():
    owned = {"spaghetti", "ground beef", "tomato sauce"}
    assert possible_dinners(owned) == ["Spaghetti Bolognese"]
