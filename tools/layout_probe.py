#!/usr/bin/env python3
"""Layout probe: render every tab at several window sizes and report layout defects.

Usage: QT_QPA_PLATFORM=offscreen /usr/bin/python3 tools/layout_probe.py [outdir]
Writes PNGs named <Tab>_<WxH>.png and prints a defect report to stdout.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import QApplication, QWidget, QAbstractButton, QLabel, QLineEdit  # noqa: E402
from PyQt6.QtCore import QSize  # noqa: E402

import main as app_main  # noqa: E402


def widget_path(w):
    name = w.objectName() or type(w).__name__
    p, path = w.parentWidget(), name
    while p is not None and not isinstance(p, app_main.MainWindow):
        path = f"{type(p).__name__}/{path}"
        p = p.parentWidget()
    return path


def check_overlaps(window):
    """Find sibling widgets whose geometries intersect (excluding containers)."""
    issues = []
    for cont in window.findChildren(QWidget):
        kids = [c for c in cont.findChildren(QWidget)
                if c.parentWidget() is cont and c.isVisible() and not c.isWindow()]
        rects = [(c, c.geometry()) for c in kids]
        for i in range(len(rects)):
            for j in range(i + 1, len(rects)):
                a, ra = rects[i]
                b, rb = rects[j]
                inter = ra & rb
                if inter.width() > 4 and inter.height() > 4:
                    # ignore parent/child style containments by class (layout boxes over content)
                    issues.append(f"OVERLAP {widget_path(a)} <-> {widget_path(b)} "
                                  f"({inter.width()}x{inter.height()} at {inter.x()},{inter.y()})")
    return issues


def inside_scrollarea(w):
    p = w.parentWidget()
    from PyQt6.QtWidgets import QScrollArea
    while p is not None:
        if isinstance(p, QScrollArea):
            return p
        p = p.parentWidget()
    return None


def check_clipped(window):
    """Find leaf widgets whose right/bottom edge falls outside the window.

    Widgets inside a QScrollArea may legitimately extend below the viewport
    (vertical scroll); flag those only if they stick out HORIZONTALLY.
    Widgets outside scroll areas must fit the window on both axes.
    """
    issues = []
    wsize = window.size()
    for w in window.findChildren((QAbstractButton, QLabel, QLineEdit)):
        if not w.isVisible() or not w.text():
            continue
        r = w.rect()
        tl = w.mapTo(window, r.topLeft())
        br = w.mapTo(window, r.bottomRight())
        scroll = inside_scrollarea(w)
        out_h = br.y() > wsize.height() + 2 or tl.y() < -2
        out_w = br.x() > wsize.width() + 2 or tl.x() < -2
        if scroll is not None:
            # only horizontal overflow is a defect inside a scroll area
            if out_w:
                issues.append(f"CLIPPED-H (in scroll) {type(w).__name__} '{w.text()[:40]}' "
                              f"path={widget_path(w)} rect=({tl.x()},{tl.y()})-({br.x()},{br.y()})")
        elif out_h or out_w:
            issues.append(f"CLIPPED {type(w).__name__} '{w.text()[:40]}' "
                          f"path={widget_path(w)} rect=({tl.x()},{tl.y()})-({br.x()},{br.y()})")
    return issues


def check_elided(window):
    """Labels/buttons whose RequiredSize exceeds their actual size."""
    issues = []
    fm_cache = {}
    for w in window.findChildren((QAbstractButton, QLabel)):
        if not w.isVisible() or not w.text():
            continue
        fm = w.fontMetrics()
        txt = w.text()
        # crude: compare single-line natural width vs widget width (skip wrapping labels)
        if isinstance(w, QLabel) and w.wordWrap():
            continue
        needed = fm.horizontalAdvance(txt) + w.contentsMargins().left() + w.contentsMargins().right() + 12
        if needed > w.width() * 1.02 and w.width() > 0:
            issues.append(f"ELIDE? {type(w).__name__} '{txt[:50]}' needs~{needed}px has {w.width()}px path={widget_path(w)}")
    return issues


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ad_layout_probe"
    os.makedirs(outdir, exist_ok=True)

    qapp = QApplication.instance() or QApplication(sys.argv)
    qapp.setStyle("Fusion")
    try:
        from ui_tabs import STYLESHEET
        qapp.setStyleSheet(STYLESHEET)
    except Exception:
        pass

    icon = app_main._get_app_icon()
    win = app_main.MainWindow(app_icon=icon)
    win.show()
    qapp.processEvents()

    stack = win.stack if hasattr(win, "stack") else getattr(win, "ui_stack", None)
    if stack is None:
        # discover the QStackedWidget
        from PyQt6.QtWidgets import QStackedWidget
        for sw in win.findChildren(type(win).__mro__[0].__mro__[0].__bases__):
            pass
        candidates = [c for c in win.findChildren(QWidget) if c.metaObject().className() == "QStackedWidget"]
        stack = candidates[0]

    tab_names = []
    for i in range(stack.count()):
        w = stack.widget(i)
        nm = w.objectName() or type(w).__name__
        tab_names.append(nm)

    sizes = [(900, 600), (1000, 650), (1100, 700), (1440, 900), (1920, 1040)]
    report = {}

    def force_layout():
        from PyQt6.QtWidgets import QLayout
        for _ in range(3):
            qapp.processEvents()
            for l in win.findChildren(QLayout):
                l.activate()
            qapp.processEvents()

    for sz in sizes:
        win.resize(QSize(*sz))
        force_layout()
        for i in range(stack.count()):
            stack.setCurrentIndex(i)
            qapp.processEvents()
            name = tab_names[i]
            pix = win.grab()
            fn = os.path.join(outdir, f"{i:02d}_{name.replace(' ', '_')}_{sz[0]}x{sz[1]}.png")
            pix.save(fn, "png")
            issues = check_overlaps(win) + check_clipped(win) + check_elided(win)
            if issues:
                report.setdefault(name, []).append(f"== {sz[0]}x{sz[1]} ==")
                report[name].extend("   " + s for s in issues)

    print(f"TABS: {tab_names}")
    print(f"SHOTS: {len(os.listdir(outdir))} files in {outdir}")
    if report:
        print("\n===== DEFECTS =====")
        for tab, lines in report.items():
            print(f"\n[{tab}]")
            for ln in lines:
                print(ln)
    else:
        print("\nNo overlap/clip/elide issues detected programmatically.")
    # bypass closeEvent's modal tray prompt in headless mode
    win.closeEvent = lambda e: e.accept()
    win.close()
    os._exit(0)  # hard-exit: skip Qt teardown (background threads may still run)


if __name__ == "__main__":
    main()