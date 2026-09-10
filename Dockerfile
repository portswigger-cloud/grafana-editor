FROM astral/uv:trixie-slim AS builder

WORKDIR /build

COPY pyproject.toml uv.lock README.md ./
# Interestingly, uv build and uv install will look at VIRTUAL_ENV but not uv venv
ENV VIRTUAL_ENV=/deps-venv
ENV UV_PYTHON_INSTALL_DIR=/python
# Install dependencies in a separate layer (cached when lock file unchanged)
RUN uv venv /deps-venv && uv sync --frozen --no-install-project --no-dev --active

COPY src ./src/

RUN uv build --wheel
ENV VIRTUAL_ENV=/venv
RUN uv venv /venv && uv pip install --no-deps dist/*.whl

FROM gcr.io/distroless/cc-debian13

COPY --from=builder /python /python
# This might look a little magical, but it will ensure that the files from
# deps-venv (created above) end up in a separate layer, only updating it when
# needed.
COPY --from=builder /deps-venv /venv
COPY --from=builder /venv /venv

EXPOSE 8000
USER nonroot
ENTRYPOINT ["/venv/bin/grafana-editor"]
