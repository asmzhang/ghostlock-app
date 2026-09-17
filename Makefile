API ?= 35

# NDK 定位：只认环境变量与常见安装位置，**不含任何写死的本机路径**。
#   ① ANDROID_NDK_HOME / ANDROID_NDK_ROOT（最优先）
#   ② 否则从各 SDK 根的 ndk/* 里取**版本号最高**的一个（lexicographic sort 对
#      两位数主版本 x.y.z 足够，且不依赖外部 shell，Windows/macOS/Linux 一致）
_WIN := $(if $(filter Windows_NT,$(OS)),1,0)
ifeq ($(_WIN),1)
  _LAPPDATA := $(subst \,/,$(LOCALAPPDATA))
  _AHOME    := $(subst \,/,$(ANDROID_HOME))
  _ASROOT   := $(subst \,/,$(ANDROID_SDK_ROOT))
else
  _LAPPDATA :=
  _AHOME    := $(ANDROID_HOME)
  _ASROOT   := $(ANDROID_SDK_ROOT)
endif
NDK_ROOT ?= $(strip $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT)))
ifeq ($(NDK_ROOT),)
  NDK_ROOT := $(lastword $(sort \
      $(wildcard $(_AHOME)/ndk/*) \
      $(wildcard $(_ASROOT)/ndk/*) \
      $(wildcard $(_LAPPDATA)/Android/Sdk/ndk/*) \
      $(wildcard $(HOME)/Android/Sdk/ndk/*) \
      $(wildcard /opt/android-sdk/ndk/*)))
endif

# prebuilt 目录名随宿主平台/NDK 版本变化（windows-x86_64 / darwin-x86_64 / linux-x86_64…），
# 一律探测实际存在的那个，不写死。
PREBUILT := $(notdir $(firstword $(wildcard $(NDK_ROOT)/toolchains/llvm/prebuilt/*)))
ifeq ($(_WIN),1)
  CLANG_SUFFIX := .cmd
else
  CLANG_SUFFIX :=
endif
NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API)-clang$(CLANG_SUFFIX)

SRCS := \
  src/core/main.c \
  src/core/offsets_json.c \
  src/core/util.c \
  src/core/fops.c

# Headers also trigger a rebuild (e.g. a freshly --register-ed src/kernels/<release>/offsets.h).
HDRS := $(wildcard src/core/*.h src/core/*/*.h src/kernels/*.h src/kernels/*/*.h)

# Device offsets are selected at runtime from uname -r.
TARGET_CONFIG ?= target.h

CFLAGS = -O2 -flto -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H=\"$(TARGET_CONFIG)\"
LDFLAGS := -fPIE -pie -pthread -flto

.PHONY: all clean product

all: ghostlock

ghostlock: $(SRCS) $(HDRS)
	@test -n "$(NDK_ROOT)" || { echo "NDK not found: set ANDROID_NDK_HOME (or ANDROID_HOME pointing at the SDK root)."; echo "  Tip: if you keep paths in harness.local.env ->  set -a; . ./harness.local.env; set +a; make ghostlock"; exit 1; }
	@test -n "$(PREBUILT)" || { echo "No toolchains/llvm/prebuilt/*/bin under: $(NDK_ROOT)"; exit 1; }
	@echo "Using NDK compiler: $(NDK_CC)"
	@echo "Target config: $(TARGET_CONFIG)"
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o ghostlock

product: ghostlock
	@echo "=== ghostlock binary ready: ./ghostlock ==="
	@echo "Build APK: bash tools/build_apk.sh   (or: ./gradlew :app:assembleDebug)"

clean:
	rm -f ghostlock
