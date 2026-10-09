#include "plugin.h"

#include <palette/api.h>
#include <palette/utils.h>

#include "dialogs.h"

#include <QtGui>
#include <QtWidgets>

// NO_OBSOLETE_FUNCS might be overkill, so let's just define this
#if IDA_SDK_VERSION >= 750
#define ACTION_DESC_LITERAL(name, label, handler, shortcut, tooltip, icon)   \
  {                                                                          \
    sizeof(action_desc_t), name, label, handler, &PLUGIN, shortcut, tooltip, \
        icon, ADF_OT_PLUGIN                                                  \
  }
#endif

#ifndef __APPLE__
#define CMD_PALETTE_SHORTCUT "Ctrl+Shift+P"
#define NAME_PALETTE_SHORTCUT "Ctrl+P"
#else
#define CMD_PALETTE_SHORTCUT "Meta+Shift+P"
#define NAME_PALETTE_SHORTCUT "Meta+P"
#endif

#if defined(__MAC__) || defined(__LINUX__)
#include <dlfcn.h>
#endif

#ifdef __MAC__
bool mac_dlopen_workaround() {
  Dl_info res;
  if (dladdr(&PLUGIN, &res) == 0) {
    return false;
  }

  auto res_open = dlopen(res.dli_fname, RTLD_NODELETE);
  if (!res_open) {
    return false;
  }

  return true;
}
#endif

QVector<QRegularExpression> getBlacklist() {
  auto blacklist = json("config.json")["blacklist"].toArray();
  QVector<QRegularExpression> blacklist_converted;

  for (auto&& i : blacklist) {
    if (i.toString().size())
      blacklist_converted.push_back(QRegularExpression(i.toString()));
  }
  return blacklist_converted;
}

void addActions(QVector<Action>& result, const qstrvec_t& actions) {
  qstring tooltip, shortcut;
  action_state_t state;

  auto blacklist = getBlacklist();

  QRegularExpression remove_tilde("~(.*?)~");

  for (auto& item : actions) {
    // Check blacklist
    bool skip = false;
    for (auto& pattern : blacklist)
      if (pattern.match(item.c_str()).hasMatch()) {
        skip = true;
        break;
      }

    if (skip) continue;

    // Enabled actions only
    if (!get_action_state(item.c_str(), &state)) continue;

    if (state > AST_ENABLE) continue;

    // Get metadata for the action
    QString tooltip_qstr;

    get_action_label(&tooltip, item.c_str());
    get_action_shortcut(&shortcut, item.c_str());

    tooltip_qstr = QString::fromUtf8(tooltip.c_str());
    tooltip_qstr = tooltip_qstr.replace(remove_tilde, "\\1");

    result.push_back(
        Action{QString(item.c_str()), tooltip_qstr, QString(shortcut.c_str())});
  }
}

// Helper function to check if database is loaded
static bool isDatabaseLoaded() {
  qstring idb_path = get_path(PATH_TYPE_IDB);
  return !idb_path.empty();
}

void addNames(QVector<Action>& result) {
  if (!isDatabaseLoaded()) {
    return;
  }

  size_t names = get_nlist_size();

  for (size_t i = 0; i < names; i++) {
    ea_t ea = get_nlist_ea(i);
    qstring demangled_name;
    get_demangled_name(&demangled_name, ea, 0, 0, GN_SHORT);

    result.push_back(Action{QString::number(get_nlist_ea(i), 16),
                            demangled_name.c_str(), QString()});
  }
}

// Get command palette items from IDA: 1. actions, 2. names
const QVector<Action> getActions() {
  QVector<Action> result;

  qstrvec_t actions;
  get_registered_actions(&actions);

  // 0. Reserve vector to avoid multiple allocations
  result.reserve(static_cast<int>(actions.size()));

  // 1. Add actions from IDA except blacklisted identifiers
  addActions(result, actions);

  std::sort(
      result.begin(), result.begin() + result.size(),
      [](Action& lhs, Action& rhs) { return lhs.name.compare(rhs.name) < 0; });

  return result;
}

#if !SHOULD_USE_TYPEINF
qstring get_nice_struc_name(tid_t struct_) {
  auto name = get_struc_name(struct_);
  tinfo_t tif;
  auto til = get_idati();
  if (til) {
    tif.get_named_type(get_idati(), name.c_str());
    tif.print(&name);
  }
    return name;
}

void addStructs(QVector<Action>& result) {
  if (!isDatabaseLoaded()) {
    return;
  }

  int idx = get_first_struc_idx();
  while (idx != BADADDR) {
    tid_t sid = get_struc_by_idx(idx);
    result.push_back(Action{
        "struct:" + QString::number(sid),
        QString::fromStdString(get_nice_struc_name(sid).c_str()), QString()});

    idx = get_next_struc_idx(idx);
  }
}

void addEnums(QVector<Action>& result) {
  if (!isDatabaseLoaded()) {
    return;
  }

  size_t cnt = get_enum_qty();
  for (size_t i = 0; i < cnt; i++) {
    enum_t n = getn_enum(i);
    result.push_back(Action{
        "struct:" + QString::number(n),
        QString::fromStdString(get_nice_struc_name(n).c_str()), QString()});
  }
}
#else
qstring get_nice_struc_name(tid_t struct_) {
  tinfo_t tif;
  qstring name;
  auto til = get_idati();
  if (til) {
    tif.get_numbered_type(get_idati(), struct_);
    tif.print(&name);
  }
    return name;
}
#endif

void addTypes(QVector<Action> &result) {
#if SHOULD_USE_TYPEINF
  if (!isDatabaseLoaded()) {
    return;
  }
  auto til = get_idati();
  if (!til) {
    // TIL not available, skip adding types
    return;
  }
  auto count = get_ordinal_count(til);
  for (decltype(count) ordinal = 0; ordinal < count; ordinal++) {
    // NOTE: this shouldn'be freed I think? It's managed by IDA and doesn't always return the start of allocation
    const char *name = get_numbered_type_name(til, ordinal);
    if (!name) {
      // Type doesn't exist for this ordinal
      continue;
    }

    if (name[0] == '\0') {
      // Type is anonymous (not named)
      continue;
    }

    result.push_back(Action{
        "struct:" + QString::number(ordinal),
        QString::fromStdString(get_nice_struc_name(ordinal).c_str()), QString()});
  }
#else
  // 1. Add structs from IDA
  addStructs(result);

  // 2. Add enums from IDA
  addEnums(result);
#endif
}

class NamesManager {
  QHash<ea_t, int> address_to_name;
  QHash<tid_t, int> address_to_struct;
  QVector<Action> result;

  // SDK 9.4 replaces the deprecated hook_to_notification_point() callbacks with
  // event_listener_t objects. HT_IDB and HT_IDP are separate event groups and
  // event_listener_t exposes a single on_event(), so we install one listener
  // per group, each forwarding to a member handler. The &PLUGIN owner lets the
  // kernel remove them automatically when ifred is unloaded.
  struct idb_listener_t : event_listener_t {
    NamesManager* mgr;
    ssize_t idaapi on_event(ssize_t code, va_list va) override {
      return mgr->on_idb_event(int(code), va);
    }
  } idb_listener_;
  struct idp_listener_t : event_listener_t {
    NamesManager* mgr;
    ssize_t idaapi on_event(ssize_t code, va_list va) override {
      return mgr->on_idp_event(int(code), va);
    }
  } idp_listener_;

 public:
  NamesManager() {
    idb_listener_.mgr = this;
    idp_listener_.mgr = this;
    hook_event_listener(HT_IDB, &idb_listener_, &PLUGIN);
    hook_event_listener(HT_IDP, &idp_listener_, &PLUGIN);
  }

  void init(QVector<Action>* names) {
    address_to_name.clear();
    address_to_struct.clear();

    int index = 0;
    for (auto& action : *names) {
      auto sep = action.id.indexOf(':');
      if (action.id.startsWith("struct:")) {
        address_to_struct.insert(QStringView(action.id).mid(sep + 1).toULongLong(nullptr),
                                 index);
      } else {
        address_to_name.insert(
            QStringView(action.id).mid(0, sep).toULongLong(nullptr, 16), index);
      }
      index++;
    }
  }

  void rename(ea_t address, const char* name) {
    auto it = address_to_name.find(address);
    qstring demangled_name;
    get_demangled_name(&demangled_name, address, 0, 0, GN_SHORT);

    if (it == address_to_name.end()) {
      if (result.empty()) return;  // Not initialized yet
      result.push_back(Action{QString::number(address, 16),
                              demangled_name.c_str(), QString()});
      address_to_name.insert(address, result.size() - 1);
      return;
    }

    Action& action = result[it.value()];
    action.name = QString::fromStdString(demangled_name.c_str());
    action.id = QString::number(address, 16);
  }

  void rebase(segm_move_infos_t& infos) {
    std::vector<std::pair<ea_t, ea_t>> moves;
    for (auto&& seg : infos) {
      for (auto&& key : address_to_name.keys()) {
        if (key >= seg.from && key < seg.from + seg.size) {
          moves.push_back({key, key + seg.to - seg.from});
        }
      }
    }
    for (auto&& move : moves) {
      auto index = address_to_name[move.first];
      auto& action = result[index];
      address_to_name.remove(move.first);
      action.id = QString::number(move.second, 16);
      address_to_name[move.second] = index;
    }
  }

  void update_struct(tid_t id, const char* name) {
    if (result.empty()) return;  // Not initialized yet

    auto it = address_to_struct.find(id);
    if (it == address_to_struct.end()) {
      result.push_back(
          Action{"struct:" + QString::number(id), name, QString()});
      address_to_struct.insert(id, result.size() - 1);
    } else {
      Action& action = result[it.value()];
      action.name = QString::fromStdString(name);
    }
  }

  void clear() {
    result.clear();
    address_to_name.clear();
    address_to_struct.clear();
  }

  void clear_struct() {
    address_to_struct.clear();
  }

  QVector<Action> get(bool clear = false) {
    if (!result.empty() && !clear) return result;

    // 1. Add names from IDA
    addNames(result);

    // 2. Add types from IDA
    addTypes(result);

    init(&result);

    return result;
  }

  ssize_t on_idb_event(int notification_code, va_list va) {
    switch (notification_code) {
      case idb_event::allsegs_moved: {
        auto info = va_arg(va, segm_move_infos_t*);
        rebase(*info);
        break;
      }
      case idb_event::renamed: {
        auto ea = va_arg(va, ea_t);
        auto new_name = va_arg(va, const char*);
        rename(ea, new_name);
        break;
      }
#if SHOULD_USE_TYPEINF && IDA_SDK_VERSION >= 900
      case idb_event::local_types_changed: {
        // An enum is promoted to int when passed through '...', so it must be
        // read back as int and cast - reading it as the enum type is UB.
        auto ltc = static_cast<local_type_change_t>(va_arg(va, int));
        auto ordinal = va_arg(va, uint32_t);
        auto name = va_arg(va, const char *);
        switch (ltc) {
        case LTC_ADDED:
        case LTC_ALIASED:
        case LTC_EDITED:
          update_struct(ordinal, get_nice_struc_name(ordinal).c_str());
          break;
        case LTC_COMPILER:
        case LTC_DELETED:
        case LTC_NONE:
        case LTC_TIL_COMPACTED:
        case LTC_TIL_LOADED:
        case LTC_TIL_UNLOADED:
        default:
          break;
        }
        break;
      }
#else
      case idb_event::struc_renamed: {
        auto struc = va_arg(va, struc_t*);
        if (struc) {
          auto tid = struc->id;
          update_struct(tid, get_nice_struc_name(tid).c_str());
        }
        break;
      }
      case idb_event::struc_created:
      case idb_event::enum_created:
      case idb_event::enum_renamed: {
        auto tid = va_arg(va, tid_t);
        update_struct(tid, get_nice_struc_name(tid).c_str());
      }
#endif
    default:
        break;
    }
    return 0;
  }

  ssize_t on_idp_event(int notification_code, va_list va) {
    switch (notification_code) {
      case processor_t::ev_term:
        clear();
    }
    return 0;
  }
};

QVector<Action> getNames(bool clear = false) {
  static NamesManager* manager;

  if (!manager) {
    manager = new NamesManager();
  }

  return manager->get();
}

class command_palette_handler : public action_handler_t {
  int idaapi activate(action_activation_ctx_t* context) override {
    qstring shortcut;
    get_action_shortcut(&shortcut, context->action);
    shortcut.replace("-", "+");
    show_palette("command palette", "Enter action or option name...",
                 getActions(), shortcut.c_str(), [](Action& action) {
                   process_ui_action(action.id.toStdString().c_str());
                   return true;
                 });
    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t*) override {
    return AST_ENABLE_ALWAYS;
  }
};

void jump_to_type(unsigned long long tid) {
#if SHOULD_USE_TYPEINF
  open_loctypes_window(tid);
#else
  bool use_local_types = reg_read_bool("ifred_local_type", false);
  if (get_enum_idx(tid) == -1) {
    if (!use_local_types) {
      open_structs_window(tid);
    } else {
      struc_t* s = get_struc(tid);
      if (s) open_loctypes_window(s->ordinal);
    }
  } else {
    if (!use_local_types)
      open_enums_window(tid);
    else
      open_loctypes_window(get_enum_type_ordinal(tid));
  }
#endif
}

class name_palette_handler : public action_handler_t {
  int idaapi activate(action_activation_ctx_t* context) override {
    qstring shortcut;
    get_action_shortcut(&shortcut, context->action);
    shortcut.replace("-", "+");
    show_palette(
        "name palette" + QString(get_path(PATH_TYPE_IDB)),
        "Enter symbol name...", getNames(), shortcut.c_str(),
        [](Action& action) {
          auto&& id = action.id;
          if (id.startsWith("struct:")) {
            auto tid = QStringView(id).mid(7).toULongLong();
            jump_to_type(tid);
          } else {
            ea_t address = static_cast<ea_t>(id.toULongLong(nullptr, 16));
            jumpto(address);
            qstring name;
            get_ea_name(&name, address, 0, 0);
            reg_update_strlist("History\\$", name.c_str(), 32);
          }

          return true;
        });
    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t*) override {
    return AST_ENABLE_ALWAYS;
  }
};

class toggle_local_types_handler : public action_handler_t {
  int idaapi activate(action_activation_ctx_t* context) override {
    bool new_value = !reg_read_bool("ifred_local_type", false);
    reg_write_bool("ifred_local_type", new_value);
    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t*) override {
    return AST_ENABLE_ALWAYS;
  }
};

class settings_handler : public action_handler_t {
  int idaapi activate(action_activation_ctx_t*) override {
    show_settings_dialog();
    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t*) override {
    return AST_ENABLE_ALWAYS;
  }
};

class about_handler : public action_handler_t {
  int idaapi activate(action_activation_ctx_t*) override {
    show_about_dialog();
    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t*) override {
    return AST_ENABLE_ALWAYS;
  }
};

static command_palette_handler command_palette_handler_;
static name_palette_handler name_palette_handler_;
static toggle_local_types_handler toggle_local_types_handler_;
static settings_handler settings_handler_;
static about_handler about_handler_;

static action_desc_t command_palette_action = ACTION_DESC_LITERAL(
    "ifred:command_palette", "ifred: Command Palette",
    &command_palette_handler_, CMD_PALETTE_SHORTCUT, "command palette", -1);

static action_desc_t name_palette_action = ACTION_DESC_LITERAL(
    "ifred:name_palette", "ifred: Name Palette", &name_palette_handler_,
    NAME_PALETTE_SHORTCUT, "name palette", -1);

static action_desc_t toggle_local_types_action =
    ACTION_DESC_LITERAL("ifred:toggle_local_types", "ifred: Toggle Local Types",
                        &toggle_local_types_handler_, "",
                        "toggle local types or struct/enum view", -1);

// These two are the entries of the Edit > Plugins > ifred submenu, so their
// labels are bare: the submenu already says "ifred".
static action_desc_t settings_action =
    ACTION_DESC_LITERAL("ifred:settings", "Settings", &settings_handler_, "",
                        "ifred settings", -1);

static action_desc_t about_action = ACTION_DESC_LITERAL(
    "ifred:about", "About", &about_handler_, "", "about ifred", -1);

// Name of our submenu, as passed to create_menu()/delete_menu(). Must be unique
// across IDA, hence the prefix. Note that the *path* used to attach actions is
// built from the menu's LABEL, not this name - see the SDK's own
// plugins/idapython/examples/ui/misc/add_menus.py.
#define IFRED_MENU_NAME "ifred:menu"
#define IFRED_MENU_LABEL "ifred"
#define IFRED_MENU_PATH "Edit/Plugins/" IFRED_MENU_LABEL "/"

static bool g_menu_installed = false;
static qtimer_t g_menu_timer = nullptr;

// (Re)build Edit > Plugins > ifred > {Settings, About}.
//
// PLUGIN_HIDE stays set on purpose: it suppresses the automatic "ifred" entry
// IDA would otherwise add to Edit > Plugins, which just calls run() and does
// nothing. This submenu replaces it.
//
// Timing is the whole difficulty here, and it is subtle:
//
//  * ifred is a PLUGIN_FIX plugin, so init() runs before the Edit > Plugins
//    menu exists. create_menu()/attach_action_to_menu() do NOT fail that
//    early: IDA records the path in its menu registry and returns true (the
//    path even resolves afterwards), but nothing is ever rendered.
//  * IDA (re)generates the Plugins menu from its plugin list on its own
//    schedule - at least once between ui_database_inited and ui_ready_to_run
//    during startup, and around plugin load/unload waves (IDA loads every
//    plugin at startup, then unloads the non-KEEP ones right after
//    ui_ready_to_run; opening a database does it again). Anything we attached
//    before such a regeneration silently disappears from the rendered menu,
//    while the registry still claims it exists - so "already installed" can
//    not be trusted, and a retry must start from delete_menu().
//
// Hence: never install from init(). Instead, every event that can precede or
// cause a regeneration (ui_ready_to_run, ui_plugin_loaded, ui_plugin_unloading)
// schedules a one-shot timer, and the timer tears down and rebuilds the
// submenu once the event loop is idle again - i.e. after IDA's own rebuild.
// The timer is debounced, so a wave of 30 plugin unloads costs one rebuild.
// Because IDA fires ui_plugin_loaded for ifred itself, this also covers a
// plugin loaded long after startup.
//
// Failure is not fatal: the palettes and their shortcuts work regardless.
static void install_ifred_menu() {
  if (g_menu_installed) {
    delete_menu(IFRED_MENU_NAME);
    g_menu_installed = false;
  }

  if (!create_menu(IFRED_MENU_NAME, IFRED_MENU_LABEL, "Edit/Plugins/")) {
    msg("ifred: create_menu(\"Edit/Plugins/\") failed\n");
    return;
  }

  // SETMENU_INS, not SETMENU_APP: the submenu is empty at this point, so there
  // is nothing for "append after" to anchor to.
  bool ok = true;
  if (!attach_action_to_menu(IFRED_MENU_PATH, settings_action.name,
                             SETMENU_INS)) {
    msg("ifred: attach Settings to \"%s\" failed\n", IFRED_MENU_PATH);
    ok = false;
  }
  if (!attach_action_to_menu(IFRED_MENU_PATH, about_action.name, SETMENU_INS)) {
    msg("ifred: attach About to \"%s\" failed\n", IFRED_MENU_PATH);
    ok = false;
  }

  if (!ok) {
    // Leave no half-built menu behind; the name must be free for a retry.
    delete_menu(IFRED_MENU_NAME);
    return;
  }

  g_menu_installed = true;
}

static int idaapi menu_timer_cb(void*) {
  g_menu_timer = nullptr;
  install_ifred_menu();
  return -1;  // one-shot
}

static void schedule_menu_install() {
  if (g_menu_timer) return;  // already pending; the last event of a wave wins
  g_menu_timer = register_timer(50, menu_timer_cb, nullptr);
  if (!g_menu_timer) install_ifred_menu();  // no timers (headless): try now
}

// SDK 9.4 event listener replacing the deprecated HT_UI notification callback.
// &PLUGIN as owner lets the kernel auto-remove it on unload; we also unhook it
// explicitly in term().
struct ui_listener_t : event_listener_t {
  ssize_t idaapi on_event(ssize_t code, va_list) override {
    switch (code) {
      // Every event that can precede or cause an Edit>Plugins regeneration -
      // including opening a database (ui_database_inited), which regenerates
      // the menu AFTER our startup install and used to wipe the submenu with
      // nothing re-triggering a rebuild (seen on macOS).
      case ui_ready_to_run:
      case ui_plugin_loaded:
      case ui_plugin_unloading:
      case ui_database_inited:
        schedule_menu_install();
        break;
      default:
        break;
    }
    return 0;
  }
};
static ui_listener_t g_ui_listener;

//--------------------------------------------------------------------------
bool idaapi run(size_t) { return true; }

extern char comment[], help[], wanted_name[];

//--------------------------------------------------------------------------
char comment[] = "ifred";

char help[] = "IDA palette";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overridden in plugins.cfg file

char wanted_name[] = "ifred";

// Directory containing this loaded plugin module. IDA dlopen()s plugins, so
// this resolves to <plugins>/ifred no matter which of the two plugin
// locations IDA loaded us from (the IDA installation's plugins/ or the user
// directory, e.g. ~/.idapro/plugins). The palette's writable data
// (config.json, theme/) is kept beside the binary.
static QString ModuleDir() {
#if defined(__NT__)
  char path[MAX_PATH] = {};
  HMODULE module = nullptr;
  if (!GetModuleHandleExA(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          (LPCSTR)&ModuleDir, &module) ||
      !GetModuleFileNameA(module, path, sizeof(path))) {
    return QString();
  }
  return QFileInfo(QString::fromLocal8Bit(path)).absolutePath();
#elif defined(__MAC__) || defined(__LINUX__)
  Dl_info info;
  if (dladdr((void*)&ModuleDir, &info) == 0 || info.dli_fname == nullptr) {
    return QString();
  }
  return QFileInfo(QString::fromLocal8Bit(info.dli_fname)).absolutePath();
#else
  return QString();
#endif
}

// Recursively copy src into dst (dst is created). Existing files are not
// overwritten - QFile::copy fails on them, which callers treat as an error.
static bool CopyRecursive(const QString& src, const QString& dst) {
  QDir src_dir(src);
  if (!src_dir.exists()) return false;
  if (!QDir().mkpath(dst)) return false;

  const QFileInfoList entries =
      src_dir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
  for (const QFileInfo& entry : entries) {
    const QString dst_path = dst + "/" + entry.fileName();
    if (entry.isDir()) {
      if (!CopyRecursive(entry.absoluteFilePath(), dst_path)) return false;
    } else if (!QFile::copy(entry.absoluteFilePath(), dst_path)) {
      return false;
    }
  }
  return true;
}

QString IdaPluginPath(const char* filename) {
  static QString g_plugin_path;
  if (g_plugin_path.size()) {
    QString r = g_plugin_path + filename;
    return r;
  }

  // Data lives next to the plugin binary: <plugins>/ifred/palette/. When the
  // module path can't be resolved, fall back to the legacy location in the
  // user directory.
  const QString module_dir = ModuleDir();
  g_plugin_path = module_dir.isEmpty()
                      ? QString(get_user_idadir()) + "/plugins/palette/"
                      : module_dir + "/palette/";
  QDir plugin_dir(g_plugin_path);
  plugin_dir.mkpath(".");

  return g_plugin_path + filename;
}

// One-time migration from the pre-folder layout: the palette data used to
// live in <user idadir>/plugins/palette/. If that directory still exists and
// the new location has no config.json yet, carry the user's settings and
// themes over. The old directory is never touched.
static void MigrateLegacyPaletteData() {
  const QString legacy_dir = QString(get_user_idadir()) + "/plugins/palette";
  if (!QDir(legacy_dir).exists()) return;
  if (QFile::exists(pluginPath("config.json"))) return;

  if (!CopyRecursive(legacy_dir, pluginPath(""))) {
    msg("ifred: could not migrate settings from %s (folder not writable?)\n",
        legacy_dir.toLocal8Bit().constData());
    return;
  }
  msg("ifred: migrated settings from %s\n",
      legacy_dir.toLocal8Bit().constData());
}

#if IDA_SDK_VERSION >= 750
#define INIT_RETURN_TYPE plugmod_t*
#else
#define INIT_RETURN_TYPE int
#endif

//--------------------------------------------------------------------------
INIT_RETURN_TYPE idaapi init() {
  if (!is_idaq())
    // the plugin works only with idaq
    return PLUGIN_SKIP;

  msg("loading palettes...\n");

  // 1. init IDAPython
#if PYTHON_SUPPORT
  void initpy();
  initpy();
#endif

  // 2. init theme path handler
  set_path_handler(IdaPluginPath);

  // 2.5 carry over data from the pre-folder layout, before anything reads
  // or seeds config/theme files
  MigrateLegacyPaletteData();

  if (!register_action(command_palette_action)) {
    msg("command palette action loading error\n");
    return PLUGIN_SKIP;
  };

  if (!register_action(name_palette_action)) {
    msg("name palette action loading error\n");
    return PLUGIN_SKIP;
  };

  if (!register_action(toggle_local_types_action)) {
    msg("toggle local types action loading error\n");
    return PLUGIN_SKIP;
  };

  if (!register_action(settings_action)) {
    msg("settings action loading error\n");
    return PLUGIN_SKIP;
  };

  if (!register_action(about_action)) {
    msg("about action loading error\n");
    return PLUGIN_SKIP;
  };

  // The Edit > Plugins submenu is installed from the UI listener, once the UI
  // is up. Do NOT install it here - see install_ifred_menu() for why that
  // breaks.
  hook_event_listener(HT_UI, &g_ui_listener, &PLUGIN);

#ifdef __MAC__
  if (!mac_dlopen_workaround()) {
    msg("ifred mac dlopen workaround error\n");
    return PLUGIN_SKIP;
  }
#endif

#ifdef _WIN32
  HMODULE hModule;
  if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)&init,
                         &hModule)) {
    msg("ifred windows loadlibrary workaround error");
    return PLUGIN_SKIP;
  }
#endif

  qstring shortcut, shortcut2;
  get_action_shortcut(&shortcut, "CommandPalette");
  get_action_shortcut(&shortcut2, command_palette_action.name);

  if (shortcut == "Ctrl-Shift-P" && shortcut == shortcut2)
    update_action_shortcut("CommandPalette", "");

  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term() {
  unhook_event_listener(HT_UI, &g_ui_listener);
  if (g_menu_timer) {
    // A pending rebuild must not fire into an unloaded module.
    unregister_timer(g_menu_timer);
    g_menu_timer = nullptr;
  }
  delete_menu(IFRED_MENU_NAME);
  g_menu_installed = false;
  cleanup_palettes();
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_FIX | PLUGIN_HIDE,  // plugin flags
    init,                      // initialize

    term,  // terminate. this pointer may be NULL.

    run,  // invoke plugin

    comment,  // long comment about the plugin
    // it could appear in the status line
    // or as a hint

    help,  // multiline help about the plugin

    wanted_name,  // the preferred short name of the plugin
    ""            // the preferred hotkey to run the plugin
};
