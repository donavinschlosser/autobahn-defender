#!/usr/bin/env python3
"""One-shot diagnostic: why is SettingsTab's scroll content so wide?"""
import os, sys
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from PyQt6.QtWidgets import QApplication, QWidget, QScrollArea, QLayout
import main as app_main

qapp = QApplication(sys.argv)
qapp.setStyle("Fusion")
try:
    from ui_tabs import STYLESHEET
    qapp.setStyleSheet(STYLESHEET)
except Exception:
    pass

win = app_main.MainWindow(app_icon=app_main._get_app_icon())
win.resize(900, 600)
win.show()
for _ in range(3):
    qapp.processEvents()
    for l in win.findChildren(QLayout):
        l.activate()
    qapp.processEvents()

cands = [c for c in win.findChildren(QWidget) if c.metaObject().className() == "QSettingsTab"]
from ui_tabs import SettingsTab
tab = win.findChildren(SettingsTab)[0]
scroll = tab.findChildren(QScrollArea)[0]
content = scroll.widget()
print("window 900x600; viewport:", scroll.viewport().width(), "content width:", content.width())
print("content minimumSizeHint:", content.minimumSizeHint().width(), "x", content.minimumSizeHint().height())
rows = []
for w in content.findChildren(QWidget):
    if w.parentWidget() is content or w.parentWidget() is None:
        continue
    msh = w.minimumSizeHint().width()
    label = ""
    for attr in ("text", "currentText", "placeholderText", "toolTip"):
        v = getattr(w, attr, None)
        if callable(v):
            try:
                v = v()
            except Exception:
                v = ""
        if isinstance(v, str) and v:
            label = v
            break
    rows.append((msh, type(w).__name__, label[:50], type(w.parentWidget()).__name__))
rows.sort(reverse=True)
for msh, cls, txt, par in rows[:15]:
    print(f"minW={msh:5d}  {cls:<14} parent={par:<12} '{txt}'")
os._exit(0)