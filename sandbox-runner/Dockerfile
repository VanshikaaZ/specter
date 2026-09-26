# Image every sandbox container starts from. It holds no secrets: the fake
# credentials are generated fresh for each run by image/plant.mjs.
FROM node:22-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends strace \
 && rm -rf /var/lib/apt/lists/*

# A normal, unprivileged user. Containers always run as this user with every
# Linux capability dropped (see run.mjs).
RUN useradd --create-home --uid 10001 --shell /bin/sh sandbox \
 && mkdir /work && chown sandbox:sandbox /work

COPY image/ /opt/specter/

USER sandbox
WORKDIR /work
