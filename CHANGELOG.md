# Changelog

## [2026-10-09][2026.10.09]

### Changed

* The plugin now installs self-contained into an `ifred/` folder instead of
  loose files: `<plugins>/ifred/{ida_palette64.*, ida-plugin.json}` - the
  folder-plugin layout IDA 9.x loads via the manifest. `<plugins>` is either
  the IDA installation's plugins directory or the user directory
  (`~/.idapro/plugins`, `%APPDATA%/Hex-Rays/IDA Pro/plugins`)
* The writable data moved next to the binary:
  `<plugins>/ifred/palette/{config.json, theme/}` (was
  `<user idadir>/plugins/palette/`). On first run the old location is
  migrated automatically; the old folder is left in place
* `cmake --install` / `build.py` install into `plugins/ifred/` (new
  `IDA_PLUGIN_INSTALL_SUBDIR` option in the ida-cmake submodule)
* CI `ifred-plugin.zip` now contains the `ifred/` folder layout (manifest
  next to the binaries) instead of loose files
* `ida-plugin.json`: `IDAMetadataDescriptorVersion` downgraded 2 → 1 - IDA
  9.4's local plugin loader rejects descriptor v2 manifests with
  "unsupported IDAMetadataDescriptorVersion value" and skips the plugin

### Fixed

* `Edit > Plugins > ifred` submenu disappeared after opening a database on
  macOS: the menu rebuild now also triggers on `ui_database_inited`, the event
  that precedes IDA's Plugins-menu regeneration on database open

### Upgrade notes

* Remove any old loose `plugins/ida_palette64.*` - IDA loads both the old and
  the new copy otherwise

## [2026-09-03][2026.09.03]

### Added

* IDA Pro v9.4 support - rebuilt against the IDA Pro SDK v9.4 (hotfix 1)
* Windows on ARM64 (aarch64) support
* `Edit > Plugins > ifred` menu with **Settings** and **About** entries
* Settings window with two tabs: a **Theme Selector** and an in-place
  **config.json** editor
* Light theme, and a gitkraken-light theme (gitkraken is now split into
  gitkraken-dark / gitkraken-light)
* Version information embedded in the built binaries, stamped with the build
  date (`YYYY.MM.DD`): a Windows VERSIONINFO resource, the Mach-O
  `current_version` on macOS, and a greppable `ifred version ...` string on all
  platforms

### Fixed

* Replaced the IDA SDK notification functions deprecated in 9.4
  (`hook_to_notification_point` / `unhook_from_notification_point`) with the new
  event-listener API: dedicated `event_listener_t` listener classes registered
  via `hook_event_listener` / `unhook_event_listener`. The plugin no longer
  calls any deprecated SDK function.
* gitkraken theme: list rows were unreadable (text drawn in the background
  colour); reworked and split into gitkraken-dark / gitkraken-light
* ayudark theme: black/invisible text, wrong sizing and a missing search icon
* Search-box placeholder ("Enter action or option name...") was invisible on
  the ayudark / ayumirage / ayuwhite themes
* macOS arm64 binary is now stripped at link time (`-Wl,-x`), which keeps
  `LC_ID_DYLIB` intact so the plugin loads - a post-build `strip` removed it
* Silenced a signed/unsigned comparison warning and fixed undefined behaviour
  when reading an enum back through `va_arg` in the type enumeration

### Changed

* Every theme now lives in its own folder under `theme/`, so users can add or
  remove themes and switch between them live from Settings while working in
  IDA Pro
* The default (built-in) theme is now a real `dark/` folder; ifred ships
  dark, light, solarized-dark and solarized-light (the remaining themes stay in
  the repository for manual installation)
* The palette font is now resolved per-OS and set with a single-value CSS
  `font-family` (Qt does not reliably honour multi-family lists in the palette's
  rich-text rows)

## [2026-02-16][2026.02.16]

This release is just a rebuilt for IDA Pro v9.3

## [2025-12-10][2025.12.10]

### Added

* Prevented cmake to add rpaths into binaries
* Prevented cmake to add full paths into binaries
* Prevented build system to add debug directories in windows build
* Made binaries stripped except macOs arm64
* On macOS with IDA, use Qt6 for headers but don't link - plugin will link
  IDA's Qt

### Fixed

* Made necessary changes to build on macOS
* config.json turns a folder instead of a file. now it stays as a json file
* if macOS arm64 is stripped then IDA cannot load plugin. Error message is
  `MH_DYLIB is missing LC_ID_DYLIB`. On macOS ARM64 (Apple Silicon), the
  dynamic linker (dyld) is much stricter about Mach-O header consistency
  than it is on `x86_64`.
* if IDA Pro is not loaded with a binary and the user tries to open ida
  palette by using shortcut, then IDA pro crashes. Now it opens and
  empty palette if no binary have loaded to prevent crash.

## [2025-09-14][2025.09.14]

### Added

* Support for IDA Pro v9.2 and Qt6

### Removed

* IDA Pro v9.1 support removed
* Qt5 support removed
* Created a new branch for IDA pro v9.1 and Qt5

## [2024-10-29][2024.10.29]

### Added

* IDA Pro v9.0 support
* Prebuilt binaries provided

[2026.10.09]: https://github.com/blue-devil/ifred/compare/v2026.09.03...HEAD
[2026.09.03]: https://github.com/blue-devil/ifred/compare/v2026.02.16...v2026.09.03
[2026.02.16]: https://github.com/blue-devil/ifred/compare/v2025.12.10...v2026.02.16
[2025.12.10]: https://github.com/blue-devil/ifred/compare/v2025.09.14...v2025.12.10
[2025.09.14]: https://github.com/blue-devil/ifred/compare/v2024.10.29...v2025.09.14
[2024.10.29]: https://github.com/blue-devil/ifred/releases/tag/v2024.10.29
