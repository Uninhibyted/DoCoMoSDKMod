# sdkmod

A drop-in mod for NTT DoCoMo's i-appli SDK emulators (Star 2.0, Star 1.5, DoJa 5.1):

- resizable window with the screen scaled to fit
- game-only mode (skin and keypad hidden)
- key remapping
- right-click menu and hotkeys: Ctrl+1–4 size, Ctrl+K keypad, Ctrl+S smoothing

Works on Windows, Wine and CrossOver.

## Install

In the SDK's `bin` folder:

1. Rename `libEGL.dll` to `libEGL_stock.dll`.
2. Copy sdkmod's `libEGL.dll` in.
3. Optionally add `sdkmod.ini` (commented sample in this repo).

To undo, rename `libEGL_stock.dll` back.

## Settings

`sdkmod.ini`, or environment variables (which take priority):

| `sdkmod.ini` | Environment | |
|---|---|---|
| `game_only = 1` | `SDKMOD_GAME_ONLY=1` | hide the skin |
| `scale = n` | `SDKMOD_SCALE=n` | starting size, 1–4 |
| `smooth = 1` | `SDKMOD_SMOOTH=1` | smooth scaling |
| `context_menu = 0` | `SDKMOD_NO_CONTEXT_MENU=1` | no right-click menu |
| `keylog = 1` | `SDKMOD_KEYLOG=1` | log key presses |
| `[keys]` | `SDKMOD_KEYS=from:to,...` | remap keys (names in the ini, hex codes in the env) |

It logs to `sdkmod.log` next to the DLL.

## How it works

sdkmod is built as `libEGL.dll`, which the emulators load from their own folder. It forwards all
of the stock DLL's exports to `libEGL_stock.dll` (`libEGL.def`), so OpenGL still works, and hooks
the emulator's drawing, windows and keys. On Star it also loads itself into `star.exe`, which
owns the window frame.

## Build

    ./build.sh    # needs i686-w64-mingw32-gcc; writes build/libEGL.dll

## Limitations

- DoJa 1.0–5.0 aren't supported (no `libEGL.dll`).
- DoJa 5.1 has no Clear key or soft keys 3–4; `#` can't be remapped.
- The full skin (Ctrl+K) doesn't scale.

Workarounds for Wine and macOS are tagged `[Wine]` and `[CrossOver/Mac]` in `sdkmod.c`.

Not affiliated with NTT DoCoMo. No DoCoMo files are included.
