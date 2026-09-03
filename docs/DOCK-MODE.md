# Dock mode: keeping the panel on screen

Why `TICKOVER_DOCK` exists, and how the dock-mode window behaves.

macOS silently discards a status item when the menu bar is full. Every API still
reports it as created and visible, there is no overflow affordance, and the icon
simply never draws — so a tray-only app becomes unreachable, including its own
settings. This is not specific to this app: a bare `NSStatusItem` behaves the
same, and the icon reappears the moment another menu-bar app frees a slot.

**Dock mode** is the way out. It keeps the ordinary activation policy, so the
panel is always reachable from the Dock and the app switcher:

```bash
open --env TICKOVER_DOCK=1 "/Applications/Tickover.app"
```

The setting persists, so afterwards a normal launch is enough. Clicking the Dock
icon toggles the panel, the window can be dragged by its background, and it
reopens where you left it — unless you opened it from the status item, which
puts it back under that icon. `TICKOVER_DOCK=0` turns it back off.

**The menu-bar item is still created.** Dock mode adds a second way in rather
than replacing the first: when the bar does have room, the item is where the
numbers live, and there is no reason to give it up for an escape hatch. Both
being live needs one rule, because clicking the status item also activates the
app and dock mode restores the panel on exactly that activation: a click on the
status item owns the activation it causes, so the click toggles the panel once
instead of twice.

That click owns *where* the panel goes, too. A dock-mode window is placed once
and then left alone, because it is a window you can drag and re-placing it on
every show would throw away wherever you put it — but a click on the status item
is the one show that names a place, so it goes under the icon it was launched
from. A Dock click, a second launch and Cmd-Tab all leave the window where it
sits.

**On Windows it is the same switch for a different reason.** Nothing there
drops a tray icon, so the escape hatch is not needed — but the flyout is
*transient*: clicking anywhere outside it dismisses it, which is what a flyout
is supposed to do and is wrong if you want the numbers left on screen while
you work. Dock mode is how you get that. The window stops hiding on focus
loss, keeps a taskbar button and an Alt-Tab entry of its own, and can be
dragged wherever you want it:

```powershell
$env:TICKOVER_DOCK = "1"; .\tickover.exe
```

The setting persists, so later launches need nothing; `"0"` turns it back off.

The app cannot tell you *when* to switch it on, because macOS does not say
whether an item was dropped: `NSStatusItem.isVisible` reports what the app
asked for, not what is on screen ([FB7087526][fb1] is still open), and reading
the item's own window frame gives a placeholder rather than its place in the
bar. Menu-bar managers work around this by listing on-screen windows at the
status-item layer, which macOS 26 broke as well — every item now reports as
belonging to Control Center ([FB18327911][fb2]). So this stays a switch you
throw, not a guess this app makes.

[fb1]: https://github.com/feedback-assistant/reports/issues/37
[fb2]: https://github.com/feedback-assistant/reports/issues/679
