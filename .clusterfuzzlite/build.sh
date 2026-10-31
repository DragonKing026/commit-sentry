#!/bin/bash -eu
# ClusterFuzzLite build script: packages every fuzz/fuzz_*.py target with PyInstaller into $OUT.
# commit-sentry is pure Python (standard library only), so nothing is installed and no sanitizer
# library is preloaded (see the ClusterFuzzLite Python integration guide).

for fuzzer in "$SRC"/commit-sentry/fuzz/fuzz_*.py; do
  fuzzer_basename=$(basename -s .py "$fuzzer")
  fuzzer_package="${fuzzer_basename}.pkg"

  pyinstaller --distpath "$OUT" --onefile --name "$fuzzer_package" \
    --paths "$SRC/commit-sentry/hooks" --hidden-import commit_sentry "$fuzzer"

  # Execution wrapper; "LLVMFuzzerTestOneInput" is the marker ClusterFuzzLite uses to detect fuzzers.
  cat > "$OUT/$fuzzer_basename" <<WRAPPER
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \
\$this_dir/$fuzzer_package "\$@"
WRAPPER
  chmod +x "$OUT/$fuzzer_basename"

  # libFuzzer dictionary next to the target (picked up by name).
  if [[ -f "${fuzzer%.py}.dict" ]]; then
    cp "${fuzzer%.py}.dict" "$OUT/$fuzzer_basename.dict"
  fi
done
