# Anti-Macro / Touch Detection — ACE's Auto-Clicker Catcher

ACE has a comprehensive **touch-input analysis** subsystem to detect auto-clickers, macros, and cloud-phone synthetic input. This is critical for catching cheats that automate gameplay.

## How it works

ACE wraps the game's touch event listener with `com.gamesafe.ano.TouchListenerProxy` (a Java class). Every touch event flows through this proxy first, allowing ACE to:
1. Record the (x, y, pressure, timestamp) tuple
2. Run statistical analysis on the touch pattern
3. Detect non-human characteristics (perfectly periodic, machine-precision coordinates, etc.)
4. Report findings to native ACE

## The Touch listener API

| String ID | API | Purpose |
|---|---|---|
| 59995 | `com/gamesafe/ano/TouchListenerProxy` | The Java proxy class |
| 60033 | `()Lcom/gamesafe/ano/TouchListenerProxy;` | Getter signature |
| 42106 | `setOnTouchListener` | Java method to install proxy |
| 42127 | `(Landroid/view/View$OnTouchListener;)V` | Method signature |

The flow:
```
Java game code:
  view.setOnTouchListener(myListener)
       ↓ (intercepted by ACE)
View.setOnTouchListener(new TouchListenerProxy(myListener))
       ↓
TouchListenerProxy.onTouch(event):
  - Forward to original listener (game gets event)
  - ALSO log to ACE for analysis
```

## Recording API (native side)

| String ID | API | Purpose |
|---|---|---|
| 15288 | `RecordTouchEnable` | Enable touch recording |
| 15308 | `RecordTouchStart` | Start recording session |
| 15327 | `RecordTouchStop` | Stop recording |
| 8092 | `is_touch_result_bt` | Threshold-comparison query |

## Detection thresholds and configurables

| String ID | Name | Purpose |
|---|---|---|
| 41553 | `ano_touch_thres` | Touch threshold (frequency, regularity, etc.) |
| 41624 | `ano_touch_reg` | Touch regularity threshold |
| 41676 | `ano_touch_period` | Touch period threshold |
| 41701 | `opt_anti_clicker` | Optional anti-clicker flag |

## Strategy keys for anti-clicker

| String ID | Strategy |
|---|---|
| 41508 | `anti_clicker` |
| 41523 | `anti_clicker2` |
| 49453 | `AntiAutoClicker` (master) |
| 15261 | `start_anti_auto_clicker2` |

## Specifically detected apps

| String ID | Package |
|---|---|
| 18012 | `net.aisence.Touchelper` |
| 18867 | `com.scriptelf.oneclickplay` |
| 35339 | `/data/data/com.smedialink.oneclickroot` |

These are popular Chinese Android auto-click apps. ACE checks if any are installed.

## Cloud-phone macro detection

| String ID | Indicator |
|---|---|
| 57695 | `ro.com.cph.remote_input_method` |
| 57825 | `com.cph.cme.use_uinput` |

These are Tencent Cloud Phone (CPH) properties. When set, the device is a cloud phone and synthetic input via `uinput` is allowed. ACE flags this as a strong "you're not a real user" indicator.

## Detection algorithm (educated guess)

Based on the threshold names:
1. **`ano_touch_period`**: Time between consecutive touches. Auto-clickers fire at near-perfect intervals; humans have natural jitter.
2. **`ano_touch_reg`**: Regularity score. Compute variance of inter-touch intervals; very low variance = bot.
3. **`ano_touch_thres`**: Decision threshold. If regularity > thres for N consecutive samples → flag as bot.

ACE may also check coordinate precision — auto-clickers often use exact pixel coordinates while humans tap "around" a button.

## Bypass implications

If our cheat triggers **macro-like behavior** (e.g., perfectly-timed reload), ACE could detect it. Our current cheats (slomo via Lua TimeDilation) don't generate fake touches — they modify game state directly. So we're not flagged by this subsystem.

If we ever added macro features (auto-loot, auto-reload):
- Add jitter to timings (random ±10% delay)
- Add coordinate fuzz (random ±5px around target)
- Or hook `TouchListenerProxy.onTouch()` to drop our synthetic events from ACE's logging

## To-do

- Find the function that installs `TouchListenerProxy` in Java (likely in libanogs JNI)
- Decompile the regularity-check algorithm
- Cross-reference with `setOnTouchListener` hook chain
- Test if our slomo (Lua-side time dilation) triggers any anti-macro flag (timing-based)
