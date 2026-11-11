# LightHouse Enterprise server image. Build context: server/.
#
#   docker build -t lighthouse-server .
#
# Supply chain (CLAUDE.md rule 12): base images are pinned by exact tag AND index digest,
# so a re-pushed tag cannot change what we build on; dependencies come only from uv.lock
# (`--frozen`). Bump a pin by updating tag and digest together.
#
# No secrets are baked in: no ARG/ENV carries a credential, and .dockerignore keeps .env
# files and keys out of the build context. Configuration arrives at run time as LH_*
# environment variables from the hosting platform's secret store.

# Same uv release as CI (UV_VERSION in .github/workflows/ci.yml).
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build

COPY --from=uv /uv /usr/local/bin/uv

# Use the image's own Python; never download one at build time.
ENV UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /src

# Dependencies first, so source edits do not invalidate the dependency layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
# Non-editable: the runtime stage needs only the virtualenv, not the source tree.
RUN uv sync --frozen --no-dev --no-editable


FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime

# A fixed, unprivileged user. The application files stay owned by root, so a compromised
# process cannot rewrite its own code.
RUN groupadd --system --gid 10001 lighthouse \
    && useradd --system --uid 10001 --gid lighthouse --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin lighthouse

COPY --from=build /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
USER 10001:10001
EXPOSE 8000

# --no-server-header: do not advertise the server software and version.
CMD ["uvicorn", "--factory", "lighthouse.main:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
