#!/bin/bash
# build_engine.sh
# Собирает construct-engine как ConstructEngine.xcframework
# и генерирует UniFFI Swift-биндинги для iOS/macOS.
#
# ИСПОЛЬЗОВАНИЕ:
#   ./build_engine.sh              # iOS device + Simulator + macOS (полный dist)
#   ./build_engine.sh --ios        # только iOS device (arm64)
#   ./build_engine.sh --sim        # только iOS Simulator (arm64 + x86_64 fat)
#   ./build_engine.sh --mac        # только macOS native (arm64)
#   ./build_engine.sh --bindings   # только Swift-биндинги (без сборки)
#   ./build_engine.sh --clean      # cargo clean перед сборкой
#   ./build_engine.sh --debug      # debug profile
#
# РЕЗУЛЬТАТ:
#   ConstructEngine.xcframework/   — xcframework для Xcode
#   construct_engine.swift         — UniFFI-generated Swift bindings (добавить в Xcode)
#   construct_engineFFI.h          — C-заголовок FFI (только для справки)

set -e
set -o pipefail

# ── Цвета ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✅${NC} $1"; }
fail() { echo -e "${RED}❌  $1${NC}"; exit 1; }
info() { echo -e "${BLUE}▸${NC}  $1"; }
warn() { echo -e "${YELLOW}⚠️${NC}   $1"; }
hdr()  { echo -e "\n${BOLD}━━━  $1  ━━━${NC}"; }

# ── Пути ──────────────────────────────────────────────────────────────────────
ENGINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MESSENGER_ROOT="$(cd "$ENGINE_ROOT/../construct-messenger" 2>/dev/null && pwd)" || \
  MESSENGER_ROOT="$ENGINE_ROOT/../../construct-messenger"
[ -d "$MESSENGER_ROOT" ] || \
  fail "construct-messenger не найден рядом с construct-engine."

XCFW_DEST="$MESSENGER_ROOT/ConstructEngine.xcframework"
SWIFT_DEST="$MESSENGER_ROOT/ConstructMessenger"
TMP="$ENGINE_ROOT/.build_tmp"

# ── Аргументы ─────────────────────────────────────────────────────────────────
BUILD_IOS=true
BUILD_SIM=true
BUILD_MAC=true
BINDINGS_ONLY=false
DO_CLEAN=false
PROFILE="release"
CARGO_FLAGS="--release"

for arg in "$@"; do
  case "$arg" in
    --ios)      BUILD_SIM=false; BUILD_MAC=false ;;
    --sim)      BUILD_IOS=false; BUILD_MAC=false ;;
    --mac)      BUILD_IOS=false; BUILD_SIM=false ;;
    --bindings) BINDINGS_ONLY=true ;;
    --clean)    DO_CLEAN=true ;;
    --debug)    PROFILE="debug"; CARGO_FLAGS="" ;;
    -h|--help)
      echo "Использование: $0 [--ios] [--sim] [--mac] [--bindings] [--clean] [--debug]"
      exit 0 ;;
    *) warn "Неизвестный аргумент: $arg" ;;
  esac
done

# ── Проверка зависимостей ─────────────────────────────────────────────────────
hdr "Проверка зависимостей"
command -v cargo    &>/dev/null || fail "cargo не установлен (https://rustup.rs)"
command -v libtool  &>/dev/null || fail "libtool не найден (Xcode Command Line Tools)"
BINDGEN_CMD=""
for cmd in uniffi-bindgen uniffi-bindgen-cli; do
  if command -v "$cmd" &>/dev/null; then
    BINDGEN_CMD="$cmd"; break
  fi
done
[ -n "$BINDGEN_CMD" ] || \
  fail "uniffi-bindgen не найден.\n  cargo install uniffi-bindgen  (версия 0.30)"
ok "cargo $(cargo --version | cut -d' ' -f2) | $BINDGEN_CMD | libtool"

# ── cargo clean ───────────────────────────────────────────────────────────────
if $DO_CLEAN; then
  hdr "Cargo clean"
  cd "$ENGINE_ROOT" && cargo clean
  ok "Кеш очищен"
fi

rm -rf "$TMP" && mkdir -p "$TMP"

# ── Генерация UniFFI Swift-биндингов ─────────────────────────────────────────
# uniffi-bindgen требует dylib (не .a) для извлечения метаданных.
# Собираем нативный macOS dylib только для генерации (не включается в xcframework).
generate_bindings() {
  hdr "Генерация Swift-биндингов (UniFFI)"
  cd "$ENGINE_ROOT"
  local host_dylib="$ENGINE_ROOT/target/debug/libconstruct_engine.dylib"
  if [ ! -f "$host_dylib" ]; then
    info "Сборка macOS debug dylib для UniFFI metadata…"
    IPHONEOS_DEPLOYMENT_TARGET="" \
    cargo build --lib --features ios 2>&1 \
      | grep -E "^error|^warning\[|Compiling construct-engine|Finished" || true
  fi
  [ -f "$host_dylib" ] || fail "Host dylib не найден: $host_dylib"

  info "Генерируем биндинги из $host_dylib…"
  $BINDGEN_CMD generate \
    --library "$host_dylib" \
    --language swift \
    --out-dir "$TMP/bindings" 2>&1 || \
    fail "$BINDGEN_CMD generate завершился с ошибкой"

  # Копируем Swift-файл в проект
  cp "$TMP/bindings/construct_engine.swift" "$SWIFT_DEST/construct_engine.swift"
  ok "construct_engine.swift → $SWIFT_DEST"

  # Сохраняем заголовки для xcframework
  cp "$TMP/bindings/construct_engineFFI.h"          "$TMP/construct_engineFFI.h"
  cp "$TMP/bindings/construct_engineFFI.modulemap"  "$TMP/module.modulemap" 2>/dev/null || \
    create_modulemap "$TMP/module.modulemap"
  ok "Заголовки FFI сохранены"
}

create_modulemap() {
  cat > "$1" << 'EOF'
module ConstructEngineFFI {
    umbrella header "construct_engineFFI.h"
    export *
}
EOF
}

# ── Функция: сборка одного таргета ───────────────────────────────────────────
build_target() {
  local arch="$1"
  info "Сборка: $arch ($PROFILE)…"
  cd "$ENGINE_ROOT"
  local deploy_env=""
  case "$arch" in
    aarch64-apple-ios)          deploy_env="IPHONEOS_DEPLOYMENT_TARGET=18.0" ;;
    aarch64-apple-ios-sim|x86_64-apple-ios) deploy_env="IPHONEOS_DEPLOYMENT_TARGET=18.0" ;;
    aarch64-apple-darwin)       deploy_env="MACOSX_DEPLOYMENT_TARGET=15.0" ;;
  esac
  env $deploy_env cargo build --lib --target "$arch" \
    --features ios $CARGO_FLAGS 2>&1 \
    | grep -E "^error|^warning\[|Compiling construct-engine|Finished" || true
  ok "Собрано: $arch"
}

# ── Генерация ─────────────────────────────────────────────────────────────────
generate_bindings

if $BINDINGS_ONLY; then
  hdr "Готово (только биндинги)"
  exit 0
fi

# ── Сборка платформ ───────────────────────────────────────────────────────────
hdr "Сборка статических библиотек"

$BUILD_IOS && build_target "aarch64-apple-ios"

if $BUILD_SIM; then
  build_target "aarch64-apple-ios-sim"
  if ! rustup target list --installed 2>/dev/null | grep -q "x86_64-apple-ios"; then
    info "Добавление x86_64-apple-ios…"
    rustup target add x86_64-apple-ios
  fi
  build_target "x86_64-apple-ios"
fi

$BUILD_MAC && build_target "aarch64-apple-darwin"

# ── Merge + copy ──────────────────────────────────────────────────────────────
hdr "Объединение и копирование"

copy_lib() {
  local arch="$1"
  local dest="$2"
  local src="$ENGINE_ROOT/target/$arch/$PROFILE/libconstruct_engine.a"
  [ -f "$src" ] || fail "Не найдена: $src"
  cp "$src" "$dest"
  ok "$(du -sh "$dest" | cut -f1)  ← $arch"
}

if $BUILD_IOS; then
  copy_lib "aarch64-apple-ios" "$TMP/libengine_ios.a"
fi

if $BUILD_SIM; then
  lipo -create \
    "$ENGINE_ROOT/target/aarch64-apple-ios-sim/$PROFILE/libconstruct_engine.a" \
    "$ENGINE_ROOT/target/x86_64-apple-ios/$PROFILE/libconstruct_engine.a" \
    -output "$TMP/libengine_sim.a"
  ok "$(du -sh "$TMP/libengine_sim.a" | cut -f1)  ← sim fat (arm64 + x86_64)"
fi

if $BUILD_MAC; then
  copy_lib "aarch64-apple-darwin" "$TMP/libengine_mac.a"
fi

# ── Заголовки для xcframework ─────────────────────────────────────────────────
# Каждая slice xcframework нуждается в папке Headers/.
make_headers_dir() {
  local dir="$1/Headers"
  mkdir -p "$dir"
  cp "$TMP/construct_engineFFI.h" "$dir/"
  cp "$TMP/module.modulemap"      "$dir/"
}

# ── Сборка xcframework ────────────────────────────────────────────────────────
hdr "Сборка ConstructEngine.xcframework"

rm -rf "$XCFW_DEST"
mkdir -p "$XCFW_DEST"

XCODEBUILD_ARGS=()

if $BUILD_IOS; then
  local_dir="$TMP/slice_ios"
  mkdir -p "$local_dir"
  cp "$TMP/libengine_ios.a" "$local_dir/libconstruct_engine.a"
  make_headers_dir "$local_dir"
  XCODEBUILD_ARGS+=(-library "$local_dir/libconstruct_engine.a"
                    -headers "$local_dir/Headers")
fi

if $BUILD_SIM; then
  local_dir="$TMP/slice_sim"
  mkdir -p "$local_dir"
  cp "$TMP/libengine_sim.a" "$local_dir/libconstruct_engine.a"
  make_headers_dir "$local_dir"
  XCODEBUILD_ARGS+=(-library "$local_dir/libconstruct_engine.a"
                    -headers "$local_dir/Headers")
fi

if $BUILD_MAC; then
  local_dir="$TMP/slice_mac"
  mkdir -p "$local_dir"
  cp "$TMP/libengine_mac.a" "$local_dir/libconstruct_engine.a"
  make_headers_dir "$local_dir"
  XCODEBUILD_ARGS+=(-library "$local_dir/libconstruct_engine.a"
                    -headers "$local_dir/Headers")
fi

xcodebuild -create-xcframework \
  "${XCODEBUILD_ARGS[@]}" \
  -output "$XCFW_DEST" 2>&1 | grep -v "^note:" || true

[ -d "$XCFW_DEST" ] || fail "xcodebuild -create-xcframework завершился с ошибкой"
ok "ConstructEngine.xcframework → $XCFW_DEST"

# ── Очистка ───────────────────────────────────────────────────────────────────
rm -rf "$TMP"

# ── Итог ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Готово!${NC}"
echo ""
echo -e "  xcframework:   ${GREEN}$XCFW_DEST${NC}"
echo -e "  Swift bindings: ${GREEN}$SWIFT_DEST/construct_engine.swift${NC}"
echo ""
echo -e "${BOLD}Следующие шаги в Xcode:${NC}"
echo "  1. Добавить ConstructEngine.xcframework в проект (если ещё не добавлен)"
echo "  2. Убедиться, что construct_engine.swift включён в таргет"
echo "  3. ⌘⇧K — Clean Build Folder"
echo "  4. ⌘R — Build"
echo ""
