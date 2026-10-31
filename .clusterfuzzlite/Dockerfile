# ClusterFuzzLite build image (https://google.github.io/clusterfuzzlite/build-integration/python-lang/).
# base-builder-python, pinned by digest (Python 3.11.13, image built 2026-10-12).
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY . $SRC/commit-sentry
WORKDIR $SRC/commit-sentry
COPY .clusterfuzzlite/build.sh $SRC/
