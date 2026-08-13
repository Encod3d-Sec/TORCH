import os, time
import _engagement as E   # self-locates VAULT; see test_hooks.py

def test_direction_marker_lifecycle(vault):
    d = str(vault / "targets" / "acme")
    assert E.seconds_since_direction(d) is None        # never marked -> None
    E.touch_direction(d)
    s = E.seconds_since_direction(d)
    assert s is not None and s < 5                     # just marked
    p = os.path.join(d, ".last-direction")
    old = time.time() - 360                            # backdate 6 min
    os.utime(p, (old, old))
    assert E.seconds_since_direction(d) > 300
