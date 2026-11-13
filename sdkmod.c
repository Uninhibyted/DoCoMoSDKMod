/* sdkmod: in-process mod for the DoCoMo SDK emulators (Star 2.0, DoJa 5.1).
 *
 * Built as libEGL.dll: the SDK's stock libEGL.dll is renamed libEGL_stock.dll and every one of
 * its exports is forwarded there (libEGL.def), so the emulator (full.exe / doja.exe) loads the
 * mod from its own bin folder on Windows and Wine alike, and GL calls still reach the real DLL.
 *
 * Window layout (natural coordinates; Star 480x640 example):
 *
 *   Star:  iappli tool (star.exe, top-level frame, client 790x838)
 *          └ doja terminal (full.exe) paints the skin + keypad
 *            ├ system icon        20,68  480x15    status icons
 *            ├ DisplayWindow      20,83  480x676   LCD + soft-key bar
 *            └ SubDisplayWindow  530,40  120x120   rear display
 *   DoJa:  doja terminal (doja.exe) is itself the top-level window, same children.
 *
 * The emulator process lays its windows out to fill the frame and scales every blit onto them;
 * it also remaps keys and handles the hotkeys and right-click menu. The frame is made resizable
 * and aspect-locked and painted black in game-only mode; on Star that happens in star.exe, which
 * the mod loads itself into (it doesn't load libEGL).
 *
 * Settings: sdkmod.ini next to the DLL (a commented sample is in this repository), overridden by the
 * environment: SDKMOD_GAME_ONLY, SDKMOD_SCALE, SDKMOD_SMOOTH, SDKMOD_KEYS,
 * SDKMOD_NO_CONTEXT_MENU, SDKMOD_KEYLOG (see README.md). Hotkeys: Ctrl+1..4, Ctrl+K, Ctrl+S.
 *
 * Platform workarounds are tagged so they can be found with grep:
 *   [Wine]           needed under Wine (CrossOver included); harmless on Windows
 *   [CrossOver/Mac]  needed for Wine's Mac driver / macOS window behaviour; harmless elsewhere
 * Each tag says what the code does on native Windows. */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

#ifndef SDKMOD_VERSION
#define SDKMOD_VERSION "dev"   /* build.sh passes the version from VERSION */
#endif

static HMODULE self;
static int launcher;          /* this process is star.exe (owns the Star frame) */
static char ini[MAX_PATH];    /* sdkmod.ini next to the DLL */
static FILE *logf;

/* ---- logging: sdkmod.log next to the DLL ---- */

/* one write per line: star.exe and full.exe append to the same file */
static void say(const char *fmt, ...) {
  if (!logf) return;
  char line[1024];
  int n = snprintf(line, sizeof line, "%04lx ", GetCurrentThreadId());
  va_list a;
  va_start(a, fmt);
  vsnprintf(line + n, sizeof line - n - 1, fmt, a);
  va_end(a);
  strcat(line, "\n");
  fputs(line, logf);
  fflush(logf);
}

static LONG CALLBACK crash_log(EXCEPTION_POINTERS *e) {
  DWORD c = e->ExceptionRecord->ExceptionCode;
  if (c != EXCEPTION_ACCESS_VIOLATION && c != EXCEPTION_ILLEGAL_INSTRUCTION && c != EXCEPTION_STACK_OVERFLOW
      && c != EXCEPTION_INT_DIVIDE_BY_ZERO && c != EXCEPTION_PRIV_INSTRUCTION) return EXCEPTION_CONTINUE_SEARCH;
  static LONG logged;
  if (InterlockedIncrement(&logged) > 20) return EXCEPTION_CONTINUE_SEARCH;
  void *at = e->ExceptionRecord->ExceptionAddress;
  MEMORY_BASIC_INFORMATION mi = { 0 };
  char mod[MAX_PATH] = "?";
  if (VirtualQuery(at, &mi, sizeof mi)) GetModuleFileNameA((HMODULE)mi.AllocationBase, mod, MAX_PATH);
  const char *base = strrchr(mod, '\\') ? strrchr(mod, '\\') + 1 : mod;
  say("exception %08lx at %p (%s+%lx)", c, at, base, (unsigned long)((BYTE *)at - (BYTE *)mi.AllocationBase));
  return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- settings ---- */

static int env_int(const char *name, int dflt) {
  char v[32];
  return GetEnvironmentVariableA(name, v, sizeof v) ? atoi(v) : dflt;
}

/* [sdkmod] key=value in sdkmod.ini, unless the environment variable is set */
static int setting(const char *env, const char *key, int dflt) {
  return env_int(env, GetPrivateProfileIntA("sdkmod", key, dflt, ini));
}

/* ---- import-table hooking ---- */

typedef struct { const char *dll, *fn; void *hook; void **orig; } Hook;

static void patch_module(HMODULE m, const Hook *hooks, int count) {
  BYTE *b = (BYTE *)m;
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
  IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!dir.VirtualAddress) return;
  for (IMAGE_IMPORT_DESCRIPTOR *imp = (void *)(b + dir.VirtualAddress); imp->Name; imp++) {
    const char *dll = (char *)(b + imp->Name);
    IMAGE_THUNK_DATA *names = (void *)(b + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
    IMAGE_THUNK_DATA *iat = (void *)(b + imp->FirstThunk);
    for (; names->u1.AddressOfData; names++, iat++) {
      if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
      const char *fn = (char *)((IMAGE_IMPORT_BY_NAME *)(b + names->u1.AddressOfData))->Name;
      for (const Hook *h = hooks; h < hooks + count; h++) {
        if (lstrcmpiA(dll, h->dll) || strcmp(fn, h->fn)) continue;
        DWORD old;
        VirtualProtect(&iat->u1.Function, sizeof(void *), PAGE_READWRITE, &old);
        if (!*h->orig) *h->orig = (void *)iat->u1.Function;
        iat->u1.Function = (ULONG_PTR)h->hook;
        VirtualProtect(&iat->u1.Function, sizeof(void *), old, &old);
      }
    }
  }
}

/* every module loaded from the emulator's bin folder (the exe and its DLLs), in one pass */
static void patch_all(const Hook *hooks, int count) {
  char dir[MAX_PATH], path[MAX_PATH];
  GetModuleFileNameA(self, dir, MAX_PATH);
  *strrchr(dir, '\\') = 0;
  size_t dl = strlen(dir);
  MEMORY_BASIC_INFORMATION mi;
  HMODULE last = 0;
  for (BYTE *a = 0; VirtualQuery(a, &mi, sizeof mi); a = (BYTE *)mi.BaseAddress + mi.RegionSize) {
    HMODULE m = (HMODULE)mi.AllocationBase;
    if (mi.State != MEM_COMMIT || !m || m == last || m == self) continue;
    if (GetModuleFileNameA(m, path, MAX_PATH) && !_strnicmp(path, dir, dl) && path[dl] == '\\') {
      patch_module(m, hooks, count);
      last = m;
    }
  }
}

/* ---- the emulator's windows ---- */

typedef struct {
  HWND h;
  WNDPROC orig;
  RECT nat;            /* rect the emulator gave it, in its parent's coordinates */
  int ox, oy;          /* drawing at natural (x, y) lands at (ox + x*sx, oy + y*sy) */
  double sx, sy;
} Win;
enum { TERM, SYS, DISP, SUB, NWIN };
static const char *win_class[NWIN] = { "doja terminal", "system icon", "DisplayWindow", "SubDisplayWindow" };
static Win win[NWIN];
static HWND frame;              /* Star: star.exe's frame; DoJa: the terminal itself */
static HWND star_frame;         /* in star.exe: the frame it owns */
static int nat_fw, nat_fh;      /* frame client size as the emulator made it */
static volatile int game_only, smooth;   /* read by the drawing hooks on any thread */
static int context_menu_on = 1;

/* window properties on the frame, shared with star.exe's copy of the mod */
#define PROP_ASPECT_W "sdkmod.bw"  /* content box width (aspect ratio for resizing) */
#define PROP_ASPECT_H "sdkmod.bh"
#define PROP_FIXED    "sdkmod.fixed"  /* original layout: the frame keeps its size */
#define PROP_GAME     "sdkmod.game"   /* game-only: the frame paints black */
static int prop(HWND h, const char *name) { return (int)(INT_PTR)GetProp(h, name); }
static void set_prop(HWND h, const char *name, int v) { SetProp(h, name, (HANDLE)(INT_PTR)v); }

static Win *win_of(HWND h) {
  if (h) for (int i = 0; i < NWIN; i++) if (win[i].h == h) return &win[i];
  return 0;
}

static int unscaled(const Win *w) { return w->sx == 1 && w->sy == 1 && !w->ox && !w->oy; }

/* window border size of a top-level window */
static void frame_border(HWND h, int *fw, int *fh) {
  RECT z = { 0, 0, 0, 0 };
  AdjustWindowRectEx(&z, GetWindowLongA(h, GWL_STYLE), GetMenu(h) != 0, GetWindowLongA(h, GWL_EXSTYLE));
  *fw = z.right - z.left;
  *fh = z.bottom - z.top;
}

/* [CrossOver/Mac] shrinks a client size, keeping its aspect ratio, to fit the screen's work area:
 * macOS clamps a window taller than the screen, which would leave black bars at the sides. On
 * Windows the window would hang off the screen instead, so fitting is still the better result. */
static void fit_work_area(HWND h, int *cw, int *ch) {
  int fw, fh;
  MONITORINFO mi = { sizeof mi };
  frame_border(h, &fw, &fh);
  if (!GetMonitorInfoA(MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST), &mi) || *cw <= 0 || *ch <= 0) return;
  double maxw = mi.rcWork.right - mi.rcWork.left - fw, maxh = mi.rcWork.bottom - mi.rcWork.top - fh;
  double f = 1;
  if (*cw * f > maxw) f = maxw / *cw;
  if (*ch * f > maxh) f = maxh / *ch;
  if (f < 1) { *cw = (int)(*cw * f); *ch = (int)(*ch * f); }
}

/* ---- layout ---- */

/* the part of the terminal shown: everything (original layout) or status bar + display */
static void content_box(RECT *b) {
  if (game_only) UnionRect(b, &win[SYS].nat, &win[DISP].nat);
  else SetRect(b, 0, 0, nat_fw, nat_fh);
}

/* [Wine] Window moves are queued and applied one per timer tick. Moving a child window makes
 * Wine flush the parent's window surface inside SetWindowPos while it holds its USER lock, and
 * if that surface is dirty it asserts ("BUG: holding USER lock") and kills the process. Between
 * ticks the message loop flushes it safely. On Windows this only makes a relayout take a few
 * ticks (20 ms each) instead of happening at once. */
#define LAYOUT_TIMER 0x4B57
#define LAYOUT_TICK_MS 20
static RECT target[NWIN];
static int pending;             /* bit per window */
static const int move_order[NWIN] = { SYS, DISP, SUB, TERM };
static int applying;            /* inside our own SetWindowPos */
static int dirty = 1;           /* relayout on the next tick */
static int last_cw, last_ch;

static void queue_move(int i, int x0, int y0, int x1, int y1) {
  Win *w = &win[i];
  if (i != TERM) {
    int nw = w->nat.right - w->nat.left, nh = w->nat.bottom - w->nat.top;
    w->sx = nw ? (double)(x1 - x0) / nw : 1;
    w->sy = nh ? (double)(y1 - y0) / nh : 1;
    w->ox = w->oy = 0;
  }
  SetRect(&target[i], x0, y0, x1, y1);
  pending |= 1 << i;
}

/* applies the next queued move; 0 when none was needed */
static int apply_one_move(void) {
  for (int k = 0; k < NWIN; k++) {
    int i = move_order[k];
    if (!(pending & (1 << i))) continue;
    pending &= ~(1 << i);
    RECT now, *t = &target[i];
    if (!win[i].h) continue;
    GetWindowRect(win[i].h, &now);
    MapWindowPoints(HWND_DESKTOP, GetParent(win[i].h), (POINT *)&now, 2);
    if (EqualRect(&now, t)) continue;
    /* [Wine] a zero-timeout wait makes Wine flush window surfaces outside its USER lock, so the
     * move below finds the parent surface clean and has nothing to flush (the game repaints
     * constantly, so it is usually dirty). On Windows: returns immediately. */
    MsgWaitForMultipleObjectsEx(0, 0, 0, QS_ALLINPUT, 0);
    applying = 1;
    /* [Wine] NOCOPYBITS | NOREDRAW skip Wine's copy-bits step, another place it flushes under the
     * lock; the RedrawWindow below repaints instead. On Windows: an ordinary move. */
    SetWindowPos(win[i].h, 0, t->left, t->top, t->right - t->left, t->bottom - t->top,
                 SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOCOPYBITS | SWP_NOREDRAW);
    applying = 0;
    RedrawWindow(win[TERM].h, 0, 0, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
    return 1;
  }
  return 0;
}

/* lays the windows out for a frame client area of cw x ch */
static void relayout(int cw, int ch) {
  Win *t = &win[TERM];
  t->ox = t->oy = 0;
  t->sx = t->sy = 1;
  if (!game_only) {
    /* the original emulator layout: skin, keypad and panels at their natural size */
    for (int i = 0; i < NWIN; i++)
      if (win[i].h && win[i].h != frame) queue_move(i, win[i].nat.left, win[i].nat.top, win[i].nat.right, win[i].nat.bottom);
    say("layout %dx%d original", cw, ch);
    return;
  }
  RECT b;
  content_box(&b);
  double bw = b.right - b.left, bh = b.bottom - b.top;
  double s = cw / bw < ch / bh ? cw / bw : ch / bh;              /* fit, letterboxed */
  double ox = (cw - bw * s) / 2 - b.left * s, oy = (ch - bh * s) / 2 - b.top * s;
  for (int i = SYS; i < NWIN; i++) {
    Win *w = &win[i];
    if (!w->h) continue;
    if (i == SUB) { queue_move(i, -4000, -4000, -3880, -3880); continue; }   /* rear display: parked off-screen */
    queue_move(i, (int)(ox + w->nat.left * s + .5), (int)(oy + w->nat.top * s + .5),
                  (int)(ox + w->nat.right * s + .5), (int)(oy + w->nat.bottom * s + .5));
  }
  if (t->h != frame) queue_move(TERM, 0, 0, cw, ch);   /* Star: fill the frame; DoJa: it is the frame */
  say("layout %dx%d scale %.3f game", cw, ch, s);
}

/* on every timer tick: one queued move, or a relayout when the frame changed size */
static void layout_tick(void) {
  if (apply_one_move()) return;
  RECT c;
  GetClientRect(frame, &c);
  if (!dirty && c.right == last_cw && c.bottom == last_ch) return;
  dirty = 0;
  last_cw = c.right;
  last_ch = c.bottom;
  if (c.right > 0 && c.bottom > 0) relayout(c.right, c.bottom);
}

/* resizes the frame: content box x n in game-only mode, the original size otherwise */
static void set_scale(double n) {
  RECT b;
  content_box(&b);
  int cw = nat_fw, ch = nat_fh;
  if (game_only) {
    cw = (int)((b.right - b.left) * n + .5);
    ch = (int)((b.bottom - b.top) * n + .5);
    fit_work_area(frame, &cw, &ch);
  }
  int fw, fh;
  frame_border(frame, &fw, &fh);
  /* the frame procedure (in star.exe on Star) reads these */
  set_prop(frame, PROP_ASPECT_W, b.right - b.left);
  set_prop(frame, PROP_ASPECT_H, b.bottom - b.top);
  set_prop(frame, PROP_FIXED, !game_only);
  set_prop(frame, PROP_GAME, game_only);
  InvalidateRect(frame, 0, TRUE);
  /* async: on Star the frame belongs to star.exe, which may be busy */
  SetWindowPos(frame, 0, 0, 0, cw + fw, ch + fh, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_ASYNCWINDOWPOS);
  dirty = 1;
}

static double current_scale(void) {
  RECT b, c;
  content_box(&b);
  GetClientRect(frame, &c);
  double a = (double)c.right / (b.right - b.left), d = (double)c.bottom / (b.bottom - b.top);
  return a < d ? a : d;
}

/* ---- drawing hooks: blits onto the LCD windows are scaled, skin drawing can be dropped ---- */

typedef enum { DRAW, DROP, SCALE } Action;

/* what to do with drawing on DC d; *w is the window when it is one of ours */
static Action classify(HDC d, Win **w) {
  HWND h = WindowFromDC(d);   /* NULL for memory DCs: the common, cheap case */
  *w = 0;
  if (!h) return DRAW;
  /* star.exe paints its skin panel onto the frame itself; in game-only mode that would show
   * through whenever the frame is bigger than the terminal (e.g. mid-resize) */
  if (h == star_frame) return prop(h, PROP_GAME) ? DROP : DRAW;
  if (!(*w = win_of(h))) return DRAW;
  if (game_only && *w == &win[TERM]) return DROP;   /* the skin, in game-only mode */
  return unscaled(*w) ? DRAW : SCALE;
}

static void map_pt(const Win *w, LONG *x, LONG *y) {
  *x = w->ox + (int)(*x * w->sx + .5);
  *y = w->oy + (int)(*y * w->sy + .5);
}
static void map_rect(const Win *w, int *x, int *y, int *cx, int *cy) {
  LONG x0 = *x, y0 = *y, x1 = *x + *cx, y1 = *y + *cy;
  map_pt(w, &x0, &y0);
  map_pt(w, &x1, &y1);
  *x = x0; *y = y0; *cx = x1 - x0; *cy = y1 - y0;
}
static void set_stretch_mode(HDC d) {
  SetStretchBltMode(d, smooth ? HALFTONE : COLORONCOLOR);
  if (smooth) SetBrushOrgEx(d, 0, 0, 0);
}

static BOOL (WINAPI *o_BitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
static BOOL (WINAPI *o_StretchBlt)(HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
static int (WINAPI *o_StretchDIBits)(HDC, int, int, int, int, int, int, int, int, const void *, const BITMAPINFO *, UINT, DWORD);
static BOOL (WINAPI *o_PlgBlt)(HDC, const POINT *, HDC, int, int, int, int, HBITMAP, int, int);

static BOOL WINAPI h_BitBlt(HDC d, int x, int y, int cx, int cy, HDC src, int sx, int sy, DWORD rop) {
  Win *w;
  switch (classify(d, &w)) {
  case DROP: return TRUE;
  case SCALE: {
    int dx = x, dy = y, dcx = cx, dcy = cy;
    map_rect(w, &dx, &dy, &dcx, &dcy);
    set_stretch_mode(d);
    return o_StretchBlt(d, dx, dy, dcx, dcy, src, sx, sy, cx, cy, rop);
  }
  default: return o_BitBlt(d, x, y, cx, cy, src, sx, sy, rop);
  }
}
static BOOL WINAPI h_StretchBlt(HDC d, int x, int y, int cx, int cy, HDC src, int sx, int sy, int scx, int scy, DWORD rop) {
  Win *w;
  switch (classify(d, &w)) {
  case DROP: return TRUE;
  case SCALE: map_rect(w, &x, &y, &cx, &cy); set_stretch_mode(d); break;
  default: break;
  }
  return o_StretchBlt(d, x, y, cx, cy, src, sx, sy, scx, scy, rop);
}
static int WINAPI h_StretchDIBits(HDC d, int x, int y, int cx, int cy, int sx, int sy, int scx, int scy,
                                  const void *bits, const BITMAPINFO *bi, UINT usage, DWORD rop) {
  Win *w;
  switch (classify(d, &w)) {
  case DROP: return scy;
  case SCALE: map_rect(w, &x, &y, &cx, &cy); set_stretch_mode(d); break;
  default: break;
  }
  return o_StretchDIBits(d, x, y, cx, cy, sx, sy, scx, scy, bits, bi, usage, rop);
}
/* Star presents each LCD frame with one PlgBlt */
static BOOL WINAPI h_PlgBlt(HDC d, const POINT *p, HDC src, int sx, int sy, int cx, int cy, HBITMAP mask, int mx, int my) {
  Win *w;
  switch (classify(d, &w)) {
  case DROP: return TRUE;
  case SCALE: {
    POINT q[3];
    for (int i = 0; i < 3; i++) { q[i] = p[i]; map_pt(w, &q[i].x, &q[i].y); }
    set_stretch_mode(d);
    return o_PlgBlt(d, q, src, sx, sy, cx, cy, mask, mx, my);
  }
  default: return o_PlgBlt(d, p, src, sx, sy, cx, cy, mask, mx, my);
  }
}

/* Game-only mode: DoJa redraws the rear display's frame onto its top-level terminal with
 * Rectangle, outside WM_PAINT, which would show through the scaled screen. (Of the skin's other
 * GDI calls - FillRect, TextOutA, Ellipse, Arc, Pie - none reach the terminal once its WM_PAINT
 * is painted black, on DoJa 5.1 or Star 2.0. Ellipse may still be worth hooking if the "device
 * on/off" panel, which games update with vibration or the backlight, ever shows through.) */
static BOOL (WINAPI *o_Rectangle)(HDC, int, int, int, int);
static BOOL WINAPI h_Rectangle(HDC d, int l, int t, int r, int b) {
  Win *w;
  return classify(d, &w) == DROP || o_Rectangle(d, l, t, r, b);
}

static const Hook hooks[] = {
  { "GDI32.dll", "BitBlt", h_BitBlt, (void **)&o_BitBlt },
  { "GDI32.dll", "StretchBlt", h_StretchBlt, (void **)&o_StretchBlt },
  { "GDI32.dll", "StretchDIBits", h_StretchDIBits, (void **)&o_StretchDIBits },
  { "GDI32.dll", "PlgBlt", h_PlgBlt, (void **)&o_PlgBlt },
  { "GDI32.dll", "Rectangle", h_Rectangle, (void **)&o_Rectangle },
};

/* ---- commands: hotkeys and the right-click menu ---- */

enum { CMD_SIZE1 = 0x4B01, CMD_SIZE2, CMD_SIZE3, CMD_SIZE4, CMD_KEYPAD = 0x4B10, CMD_SMOOTH };

static void run_cmd(UINT id) {
  if (id >= CMD_SIZE1 && id <= CMD_SIZE4) {
    set_scale(id - CMD_SIZE1 + 1);
  } else if (id == CMD_KEYPAD) {
    double s = current_scale();    /* keep the size: the other mode gets the same scale */
    game_only = !game_only;
    set_scale(s);
  } else if (id == CMD_SMOOTH) {
    smooth = !smooth;
    dirty = 1;
    RedrawWindow(win[TERM].h, 0, 0, RDW_INVALIDATE | RDW_ALLCHILDREN);
  }
}

/* Ctrl+1..4, Ctrl+K, Ctrl+S; 1 when the key was one of ours */
static int hotkey(WPARAM vk) {
  if (!(GetKeyState(VK_CONTROL) & 0x8000)) return 0;
  if (vk >= '1' && vk <= '4') run_cmd(CMD_SIZE1 + (UINT)(vk - '1'));
  else if (vk == 'K') run_cmd(CMD_KEYPAD);
  else if (vk == 'S') run_cmd(CMD_SMOOTH);
  else return 0;
  return 1;
}

static void context_menu(HWND h) {
  HMENU m = CreatePopupMenu(), size = CreatePopupMenu();
  AppendMenuW(size, MF_STRING, CMD_SIZE1, L"1×\tCtrl+1");
  AppendMenuW(size, MF_STRING, CMD_SIZE2, L"2×\tCtrl+2");
  AppendMenuW(size, MF_STRING, CMD_SIZE3, L"3×\tCtrl+3");
  AppendMenuW(size, MF_STRING, CMD_SIZE4, L"4×\tCtrl+4");
  AppendMenuW(m, MF_POPUP, (UINT_PTR)size, L"Window size");
  AppendMenuW(m, MF_SEPARATOR, 0, 0);
  AppendMenuW(m, MF_STRING | (game_only ? 0 : MF_CHECKED), CMD_KEYPAD, L"Show keypad\tCtrl+K");
  AppendMenuW(m, MF_STRING | (smooth ? MF_CHECKED : 0), CMD_SMOOTH, L"Smooth scaling\tCtrl+S");
  POINT p;
  GetCursorPos(&p);
  UINT id = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, p.x, p.y, 0, h, 0);
  DestroyMenu(m);   /* destroys the submenu too */
  if (id) run_cmd(id);
}

/* ---- key remapping ---- */

/* keymap[pc key] = emulator key; 0 = not remapped, KEY_NONE = swallow the key */
#define KEY_NONE 0x100
static int keymap[256];
static int keylog;

/* PC key names for [keys] in sdkmod.ini */
static int pc_key(const char *n) {
  static const struct { const char *name; BYTE vk; } named[] = {
    {"up", VK_UP}, {"down", VK_DOWN}, {"left", VK_LEFT}, {"right", VK_RIGHT},
    {"space", VK_SPACE}, {"enter", VK_RETURN}, {"return", VK_RETURN}, {"esc", VK_ESCAPE},
    {"escape", VK_ESCAPE}, {"backspace", VK_BACK}, {"tab", VK_TAB}, {"shift", VK_SHIFT},
    {"insert", VK_INSERT}, {"delete", VK_DELETE}, {"home", VK_HOME}, {"end", VK_END},
    {"pageup", VK_PRIOR}, {"pagedown", VK_NEXT}, {"comma", VK_OEM_COMMA}, {"period", VK_OEM_PERIOD},
    {"slash", VK_OEM_2}, {"semicolon", VK_OEM_1}, {"quote", VK_OEM_7}, {"minus", VK_OEM_MINUS},
    {"equals", VK_OEM_PLUS}, {"lbracket", VK_OEM_4}, {"rbracket", VK_OEM_6}, {"backslash", VK_OEM_5},
    {"grave", VK_OEM_3},
  };
  if (n[0] && !n[1] && isalnum((unsigned char)n[0])) return toupper((unsigned char)n[0]);
  if (tolower((unsigned char)n[0]) == 'f' && isdigit((unsigned char)n[1])) {
    int f = atoi(n + 1);
    return f >= 1 && f <= 12 ? VK_F1 + f - 1 : -1;
  }
  if (!_strnicmp(n, "numpad", 6) && isdigit((unsigned char)n[6]) && !n[7]) return VK_NUMPAD0 + n[6] - '0';
  for (size_t i = 0; i < sizeof named / sizeof *named; i++) if (!_stricmp(n, named[i].name)) return named[i].vk;
  return -1;
}

/* the key the emulator reads for each phone button (Star dev guide 8.3) */
static int phone_button(const char *n) {
  static const struct { const char *name; int vk; } named[] = {
    {"up", VK_UP}, {"down", VK_DOWN}, {"left", VK_LEFT}, {"right", VK_RIGHT},
    {"select", VK_RETURN}, {"clear", VK_ESCAPE},
    {"soft1", 'A'}, {"soft2", 'S'}, {"soft3", 'Z'}, {"soft4", 'X'},
    {"star", VK_MULTIPLY}, {"*", VK_MULTIPLY}, {"none", KEY_NONE},
  };
  if (n[0] && !n[1] && isdigit((unsigned char)n[0])) return n[0];
  for (size_t i = 0; i < sizeof named / sizeof *named; i++) if (!_stricmp(n, named[i].name)) return named[i].vk;
  return -1;
}

static char *trim(char *p) {
  while (*p == ' ' || *p == '\t') p++;
  char *e = p + strlen(p);
  while (e > p && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) *--e = 0;
  return p;
}

/* [keys] in sdkmod.ini: "PC key = phone button" */
static int load_ini_keys(void) {
  static char buf[8192];
  int n = 0;
  if (!GetPrivateProfileSectionA("keys", buf, sizeof buf, ini)) return 0;
  for (char *line = buf; *line; line += strlen(line) + 1) {
    char *eq = strchr(line, '=');
    if (!eq) continue;
    *eq = 0;
    char *k = trim(line), *v = trim(eq + 1), *comment = strpbrk(v, ";#");
    if (comment) { *comment = 0; v = trim(v); }
    int from = pc_key(k), to = phone_button(v);
    if (from < 0 || to < 0) { say("sdkmod.ini [keys]: ignoring '%s = %s'", k, v); continue; }
    keymap[from] = to;
    n++;
  }
  return n;
}

/* SDKMOD_KEYS = "from:to,..." in hex virtual-key codes (to 0 = swallow), else sdkmod.ini */
static void load_keymap(void) {
  char v[2048];
  int n = 0;
  if (!GetEnvironmentVariableA("SDKMOD_KEYS", v, sizeof v)) {
    if ((n = load_ini_keys())) say("key map: %d keys from sdkmod.ini", n);
    return;
  }
  for (char *p = v, *end; *p; p = end) {
    unsigned long from = strtoul(p, &end, 16);
    if (*end != ':') break;
    unsigned long to = strtoul(end + 1, &end, 16);
    if (from < 256 && to < 256) { keymap[from] = to ? (int)to : KEY_NONE; n++; }
    while (*end == ',' || *end == ' ') end++;
  }
  say("key map: %d keys", n);
}

static void remap_key(MSG *msg) {
  UINT m = msg->message;
  int key = m == WM_KEYDOWN || m == WM_KEYUP || m == WM_SYSKEYDOWN || m == WM_SYSKEYUP;
  if (keylog && (key || m == WM_CHAR)) {
    char c[64] = "";
    GetClassNameA(msg->hwnd, c, sizeof c);
    say("key msg %04x vk %02x to %s", m, (unsigned)msg->wParam, c);
  }
  if (!key || msg->wParam >= 256 || !keymap[msg->wParam]) return;
  if (GetKeyState(VK_CONTROL) & 0x8000) return;      /* leave Ctrl shortcuts alone */
  int to = keymap[msg->wParam];
  if (to == KEY_NONE) { msg->message = WM_NULL; return; }
  msg->wParam = to;
  /* new scan code (bits 16-23) and extended-key flag (bit 24); repeat/up flags stay */
  UINT sc = MapVirtualKeyA(to, MAPVK_VK_TO_VSC);
  int ext = to == VK_UP || to == VK_DOWN || to == VK_LEFT || to == VK_RIGHT;
  msg->lParam = (msg->lParam & 0xFE00FFFF) | ((LPARAM)(sc & 0xFF) << 16) | (ext ? 0x01000000 : 0);
}

/* ---- frame behaviour: black in game-only mode, resizable, aspect-locked ---- */

/* Aspect-locked resizing.
 * [CrossOver/Mac] Wine's Mac driver reports every drag as WMSZ_BOTTOMRIGHT, so the WM_SIZING edge
 * is ignored and the dragged sides are worked out by comparing with the rect at the start of the
 * drag. During a live single-edge drag it also takes only the size from WM_SIZING and re-centres
 * the other axis, so:
 *  - corner drags (both sides moving) are aspect-locked live, anchored at the far corner;
 *  - single-edge drags resize freely (the game letterboxes) and snap to the aspect ratio on
 *    release, keeping the edges the user did not touch where they were.
 * On Windows the same logic works (edges are detected the same way); single-edge drags just snap
 * on release instead of tracking live. */
typedef enum { DRAG_UNDECIDED, DRAG_CORNER, DRAG_EDGE } DragKind;
typedef enum { WIDTH_LEADS, HEIGHT_LEADS } Axis;
static RECT drag_start;
static int dragging, keep_left, keep_top;
static DragKind drag_kind;

/* window size W x H adjusted to the content aspect ratio, the given axis leading */
static void aspect_size(HWND h, Axis lead, int *W, int *H) {
  int bw = prop(h, PROP_ASPECT_W), bh = prop(h, PROP_ASPECT_H), fw, fh;
  frame_border(h, &fw, &fh);
  int cw = *W - fw, ch = *H - fh;
  if (lead == WIDTH_LEADS) ch = cw * bh / bw; else cw = ch * bw / bh;
  fit_work_area(h, &cw, &ch);
  *W = cw + fw;
  *H = ch + fh;
}

static void paint_black(HWND h, HDC d, const RECT *r) {
  RECT all;
  if (!r) { GetClientRect(h, &all); r = &all; }
  FillRect(d, r, GetStockObject(BLACK_BRUSH));   /* our own call: not hooked */
}

/* Frame messages. Used by star.exe's frame and, on DoJa, by the top-level terminal itself. */
static LRESULT frame_msg(HWND h, UINT m, WPARAM wp, LPARAM lp, WNDPROC orig) {
  int fixed = prop(h, PROP_FIXED);
  int locked = prop(h, PROP_ASPECT_W) && prop(h, PROP_ASPECT_H) && !fixed && !(GetKeyState(VK_SHIFT) & 0x8000);
  switch (m) {
  case WM_ERASEBKGND:
    if (!prop(h, PROP_GAME)) break;
    paint_black(h, (HDC)wp, 0);
    return 1;
  case WM_PAINT:
    if (!prop(h, PROP_GAME)) break;
    {
      PAINTSTRUCT ps;
      HDC d = BeginPaint(h, &ps);
      paint_black(h, d, &ps.rcPaint);
      EndPaint(h, &ps);
    }
    return 0;
  case WM_ENTERSIZEMOVE:
    GetWindowRect(h, &drag_start);
    dragging = 1;
    drag_kind = DRAG_UNDECIDED;
    break;
  case WM_SIZING: {
    RECT *r = (RECT *)lp;
    if (fixed) {   /* original layout: the size stays */
      RECT now;
      GetWindowRect(h, &now);
      r->right = r->left + (now.right - now.left);
      r->bottom = r->top + (now.bottom - now.top);
      return TRUE;
    }
    if (!dragging || !locked) break;
    int dl = r->left != drag_start.left, dr = r->right != drag_start.right;
    int dt = r->top != drag_start.top, db = r->bottom != drag_start.bottom;
    if (drag_kind == DRAG_UNDECIDED && (dl || dr || dt || db)) {
      drag_kind = (dl || dr) && (dt || db) ? DRAG_CORNER : DRAG_EDGE;
      keep_left = !dl;
      keep_top = !dt;
    }
    if (drag_kind != DRAG_CORNER) break;
    int W = r->right - r->left, H = r->bottom - r->top;
    int dw = abs(W - (drag_start.right - drag_start.left)), dh = abs(H - (drag_start.bottom - drag_start.top));
    aspect_size(h, dw * prop(h, PROP_ASPECT_H) >= dh * prop(h, PROP_ASPECT_W) ? WIDTH_LEADS : HEIGHT_LEADS, &W, &H);
    r->left = keep_left ? drag_start.left : drag_start.right - W;
    r->right = r->left + W;
    r->top = keep_top ? drag_start.top : drag_start.bottom - H;
    r->bottom = r->top + H;
    return TRUE;
  }
  case WM_EXITSIZEMOVE:
    dragging = 0;
    if (drag_kind == DRAG_EDGE && locked) {
      RECT r;
      GetWindowRect(h, &r);
      int W = r.right - r.left, H = r.bottom - r.top;
      int horizontal = r.left != drag_start.left || r.right != drag_start.right;
      aspect_size(h, horizontal ? WIDTH_LEADS : HEIGHT_LEADS, &W, &H);
      int x = keep_left ? r.left : r.right - W, y = keep_top ? r.top : r.bottom - H;
      SetWindowPos(h, 0, x, y, W, H, SWP_NOZORDER | SWP_NOACTIVATE);
    }
    drag_kind = DRAG_UNDECIDED;
    break;
  case WM_GETMINMAXINFO: {
    /* the emulator's minimum is the whole skin; let the window shrink below it */
    LRESULT res = CallWindowProcA(orig, h, m, wp, lp);
    MINMAXINFO *mm = (MINMAXINFO *)lp;
    mm->ptMinTrackSize.x = mm->ptMinTrackSize.y = 120;
    return res;
  }
  }
  return CallWindowProcA(orig, h, m, wp, lp);
}

/* makes a top-level window resizable, keeping its client size */
static void make_resizable(HWND f) {
  RECT c;
  GetClientRect(f, &c);
  SetWindowLongA(f, GWL_STYLE, GetWindowLongA(f, GWL_STYLE) | WS_THICKFRAME | WS_MAXIMIZEBOX);
  int fw, fh;
  frame_border(f, &fw, &fh);
  SetWindowPos(f, 0, 0, 0, c.right + fw, c.bottom + fh, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

/* ---- the emulator's window procedures ---- */

static LRESULT CALLBACK emulator_proc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  Win *w = win_of(h);
  if (!w) return DefWindowProcA(h, m, wp, lp);
  if (context_menu_on && (m == WM_RBUTTONDOWN || m == WM_RBUTTONUP)) {
    if (m == WM_RBUTTONUP) context_menu(h);
    return 0;
  }
  if (m == WM_WINDOWPOSCHANGING && !applying && h != frame) {
    /* the emulator moved one of its windows: remember that as the natural rect, keep ours
     * (not for the DoJa terminal, which is the frame and resizes freely) */
    WINDOWPOS *p = (WINDOWPOS *)lp;
    if (!(p->flags & SWP_NOMOVE)) OffsetRect(&w->nat, p->x - w->nat.left, p->y - w->nat.top);
    if (!(p->flags & SWP_NOSIZE)) { w->nat.right = w->nat.left + p->cx; w->nat.bottom = w->nat.top + p->cy; }
    p->flags |= SWP_NOMOVE | SWP_NOSIZE;
    dirty = 1;
  }
  if (m >= WM_MOUSEFIRST && m <= WM_MOUSELAST && m != WM_MOUSEWHEEL && !unscaled(w)) {
    /* mouse positions back to the emulator's natural coordinates */
    int x = (short)LOWORD(lp), y = (short)HIWORD(lp);
    lp = MAKELPARAM((int)((x - w->ox) / w->sx), (int)((y - w->oy) / w->sy));
  }
  if (w == &win[TERM]) {
    /* our own resizes are none of the emulator's business (it would resize the frame to fit) */
    if (applying && (m == WM_SIZE || m == WM_MOVE)) return 0;
    if (applying && m == WM_WINDOWPOSCHANGED) return DefWindowProcA(h, m, wp, lp);
    if (m == WM_TIMER && wp == LAYOUT_TIMER) { layout_tick(); return 0; }
    /* DoJa: the terminal is the top-level window, so it also gets the frame behaviour */
    if (h == frame && (m == WM_ENTERSIZEMOVE || m == WM_SIZING || m == WM_EXITSIZEMOVE || m == WM_GETMINMAXINFO))
      return frame_msg(h, m, wp, lp, w->orig);
    if (m == WM_ERASEBKGND) { paint_black(h, (HDC)wp, 0); return 1; }   /* letterbox */
    if (m == WM_PAINT && game_only) {
      PAINTSTRUCT ps;
      HDC d = BeginPaint(h, &ps);
      paint_black(h, d, &ps.rcPaint);
      EndPaint(h, &ps);
      return 0;
    }
  }
  return CallWindowProcA(w->orig, h, m, wp, lp);
}

static void subclass(Win *w) {
  RECT r;
  GetWindowRect(w->h, &r);
  MapWindowPoints(HWND_DESKTOP, GetParent(w->h), (POINT *)&r, 2);
  w->nat = r;
  w->sx = w->sy = 1;
  w->orig = (WNDPROC)SetWindowLongPtrA(w->h, GWLP_WNDPROC, (LONG_PTR)emulator_proc);
}

/* ---- start-up ---- */

/* Everything that touches windows runs on the emulator's UI thread.
 * [Wine] Changing the emulator's windows from our own thread made Wine assert ("BUG: holding USER
 * lock"). Windows allows it, but doing it on the owning thread is correct there too. */
static HHOOK msg_hook;

static void setup_on_ui_thread(void) {
  RECT c;
  GetClientRect(frame, &c);
  nat_fw = c.right;
  nat_fh = c.bottom;
  for (int i = 0; i < NWIN; i++) if (win[i].h) subclass(&win[i]);
  if (win[TERM].h == frame) make_resizable(frame);   /* DoJa: no star.exe to do it */
  say("attached: frame %dx%d, display %ldx%ld", nat_fw, nat_fh,
      win[DISP].nat.right - win[DISP].nat.left, win[DISP].nat.bottom - win[DISP].nat.top);
  load_keymap();
  keylog = setting("SDKMOD_KEYLOG", "keylog", 0);
  game_only = setting("SDKMOD_GAME_ONLY", "game_only", 0);
  smooth = setting("SDKMOD_SMOOTH", "smooth", 0);
  context_menu_on = GetPrivateProfileIntA("sdkmod", "context_menu", 1, ini) && !env_int("SDKMOD_NO_CONTEXT_MENU", 0);
  int scale = setting("SDKMOD_SCALE", "scale", 1);
  set_scale(scale > 0 ? scale : 1);
  SetTimer(win[TERM].h, LAYOUT_TIMER, LAYOUT_TICK_MS, 0);
}

static LRESULT CALLBACK on_ui_thread(int code, WPARAM wp, LPARAM lp) {
  static int set_up;
  MSG *msg = (MSG *)lp;
  if (code == HC_ACTION && wp == PM_REMOVE) {
    if (!set_up) { set_up = 1; setup_on_ui_thread(); }
    int down = msg->message == WM_KEYDOWN || msg->message == WM_SYSKEYDOWN;
    if (down && !(msg->lParam & 0x40000000) && hotkey(msg->wParam)) msg->message = WM_NULL;   /* first press only */
    else remap_key(msg);
  }
  return CallNextHookEx(msg_hook, code, wp, lp);
}

/* a top-level window of this class that this process owns (or whose child of child_class it owns) */
static HWND find_own_window(const char *cls, const char *child_class) {
  HWND top = 0;
  while ((top = FindWindowExA(0, top, cls, 0))) {
    HWND owner = child_class ? FindWindowExA(top, 0, child_class, 0) : top;
    DWORD pid;
    if (owner && GetWindowThreadProcessId(owner, &pid) && pid == GetCurrentProcessId()) return top;
  }
  return 0;
}

static BOOL CALLBACK find_child(HWND h, LPARAM found) {
  Win *wins = (Win *)found;
  char cls[64];
  GetClassNameA(h, cls, sizeof cls);
  for (int i = SYS; i < NWIN; i++) if (!wins[i].h && !strcmp(cls, win_class[i])) wins[i].h = h;
  return TRUE;
}

/* named mutex that marks a process as already running the mod */
static void mod_mutex_name(DWORD pid, char *name) { wsprintfA(name, "Local\\sdkmod-%lu", pid); }

/* Star: star.exe owns the frame but doesn't load libEGL, so load this DLL into it. */
static void load_into(DWORD pid) {
  char name[64];
  mod_mutex_name(pid, name);
  HANDLE m = OpenMutexA(SYNCHRONIZE, FALSE, name);
  if (m) { CloseHandle(m); return; }   /* already there */
  WCHAR path[MAX_PATH];
  SIZE_T bytes = (GetModuleFileNameW(self, path, MAX_PATH) + 1) * sizeof(WCHAR);
  HANDLE p = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
  if (!p) { say("can't open process %lu (%lu)", pid, GetLastError()); return; }
  void *mem = VirtualAllocEx(p, 0, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  /* kernel32 is mapped at the same address in every 32-bit process */
  LPTHREAD_START_ROUTINE load = (LPTHREAD_START_ROUTINE)(void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
  HANDLE t = mem && WriteProcessMemory(p, mem, path, bytes, 0) ? CreateRemoteThread(p, 0, 0, load, mem, 0, 0) : 0;
  if (t) {
    WaitForSingleObject(t, 10000);
    CloseHandle(t);
    say("loaded into process %lu", pid);
  } else {
    say("couldn't load into process %lu (%lu)", pid, GetLastError());
  }
  if (mem) VirtualFreeEx(p, mem, 0, MEM_RELEASE);
  CloseHandle(p);
}

/* full.exe / doja.exe: find the terminal and its LCD windows, then hand over to the UI thread */
static void run_emulator_side(void) {
  Win found[NWIN];   /* filled here, published to win[] once complete (the hooks read win[]) */
  HWND f = 0;
  for (int tries = 0; ; tries++, Sleep(100)) {
    memset(found, 0, sizeof found);
    if ((f = find_own_window("iappli tool", "doja terminal")))     /* Star: terminal in star.exe's frame */
      found[TERM].h = FindWindowExA(f, 0, "doja terminal", 0);
    else if ((f = find_own_window("doja terminal", 0)))           /* DoJa: the terminal is the window */
      found[TERM].h = f;
    if (f) {
      EnumChildWindows(found[TERM].h, find_child, (LPARAM)found);
      if (found[DISP].h && found[SYS].h) break;
    }
    if (tries > 600) { say("no emulator window found"); return; }
  }
  frame = f;
  memcpy(win, found, sizeof win);
  DWORD frame_pid = 0;
  GetWindowThreadProcessId(frame, &frame_pid);
  if (frame_pid != GetCurrentProcessId()) load_into(frame_pid);
  DWORD ui = GetWindowThreadProcessId(win[TERM].h, 0);
  msg_hook = SetWindowsHookExA(WH_GETMESSAGE, on_ui_thread, 0, ui);
  say("message hook %p on ui thread %04lx", msg_hook, ui);
  PostMessageA(win[TERM].h, WM_NULL, 0, 0);   /* get the hook called soon */
}

/* star.exe: the frame becomes resizable, aspect-locked and black in game-only mode */
static WNDPROC frame_orig;
static LRESULT CALLBACK frame_proc(HWND h, UINT m, WPARAM wp, LPARAM lp) { return frame_msg(h, m, wp, lp, frame_orig); }

static void run_launcher_side(void) {
  HWND f = 0;
  for (int tries = 0; tries < 600 && !(f = find_own_window("iappli tool", 0)); tries++) Sleep(100);
  if (!f) return;
  star_frame = f;
  frame_orig = (WNDPROC)SetWindowLongPtrA(f, GWLP_WNDPROC, (LONG_PTR)frame_proc);
  make_resizable(f);
  say("frame made resizable");
}

static DWORD WINAPI start(void *unused) {
  char name[64];
  mod_mutex_name(GetCurrentProcessId(), name);
  CreateMutexA(0, FALSE, name);   /* kept open: tells full.exe this process already has the mod */
  AddVectoredExceptionHandler(1, crash_log);
  patch_all(hooks, sizeof hooks / sizeof *hooks);
  /* h_BitBlt scales through StretchBlt even where a module only imports BitBlt */
  if (!o_StretchBlt) o_StretchBlt = (void *)GetProcAddress(GetModuleHandleA("gdi32.dll"), "StretchBlt");
  if (launcher) run_launcher_side(); else run_emulator_side();
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, void *reserved) {
  if (why != DLL_PROCESS_ATTACH) return TRUE;
  self = h;
  DisableThreadLibraryCalls(h);
  char exe[MAX_PATH], log[MAX_PATH];
  GetModuleFileNameA(0, exe, MAX_PATH);
  launcher = !lstrcmpiA(strrchr(exe, '\\') ? strrchr(exe, '\\') + 1 : exe, "star.exe");
  GetModuleFileNameA(h, ini, MAX_PATH);
  strcpy(strrchr(ini, '\\') + 1, "sdkmod.ini");
  GetModuleFileNameA(h, log, MAX_PATH);
  strcpy(strrchr(log, '\\') + 1, "sdkmod.log");
  /* the emulator loads first and starts a fresh log; both processes then append */
  if (!launcher && (logf = fopen(log, "w"))) fclose(logf);
  logf = fopen(log, "a");
  say("sdkmod %s loaded into %s (pid %lu)", SDKMOD_VERSION, exe, GetCurrentProcessId());
  CloseHandle(CreateThread(0, 0, start, 0, 0, 0));   /* window work waits for the windows */
  return TRUE;
}
