# One image, two roles: DIODE_MODE=sender|receiver. Runtime is the Python standard library only.
# Base pinned by digest (multi-arch index of python:3.12-slim, linux/amd64 and linux/arm64).
# To move it: docker buildx imagetools inspect python:3.12-slim
FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2

ENV PYTHONUNBUFFERED=1 \
    DIODE_STATE_DIR=/var/lib/diode

# The service never installs packages, so drop pip and the build tooling from the runtime layer.
RUN groupadd --gid 10001 diode \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin diode \
 && install -d -o 10001 -g 10001 -m 0750 /var/lib/diode \
 && pip uninstall -y pip setuptools wheel >/dev/null 2>&1 || true \
 && rm -rf /root/.cache /usr/local/lib/python3.12/site-packages/pip* /usr/local/bin/pip*

WORKDIR /app
COPY --chmod=0444 protocol.py receipts.py catcher.py pitcher.py \
     diode.py diode_config.py diode_http.py diode_sender.py diode_receiver.py ./
# Byte-compile at build time so a read-only root filesystem needs no __pycache__ writes.
RUN python -m compileall -q /app

# Version metadata last, so a new revision does not rebuild the layers above.
ARG APP_VERSION=dev
ARG APP_REVISION=unknown
LABEL org.opencontainers.image.title="udp-diode" \
      org.opencontainers.image.description="One-way UDP transfer with HTTP custody on both sides" \
      org.opencontainers.image.source="https://github.com/newen-systems/udp-diode" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${APP_REVISION}"
ENV APP_VERSION=${APP_VERSION} APP_REVISION=${APP_REVISION}

USER 10001:10001
VOLUME /var/lib/diode
EXPOSE 8080/tcp 9400/udp 9401/udp
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "/app/diode.py", "--healthcheck"]
ENTRYPOINT ["python", "/app/diode.py"]
