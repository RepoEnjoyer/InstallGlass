FROM node:24.14.0-bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates strace tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/installglass
COPY env-hook.cjs proxy.mjs sandbox-runner.mjs scan.mjs ./

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "/opt/installglass/sandbox-runner.mjs"]
