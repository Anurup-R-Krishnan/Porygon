FROM python:3.13-slim-bookworm

ARG TARGETARCH=amd64
ARG TRIVY_VERSION=0.72.0
ARG TRIVY_SHA256_AMD64=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
ARG TRIVY_SHA256_ARM64=2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && case "$TARGETARCH" in \
         amd64) archive_arch="64bit"; expected="$TRIVY_SHA256_AMD64" ;; \
         arm64) archive_arch="ARM64"; expected="$TRIVY_SHA256_ARM64" ;; \
         *) echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${archive_arch}.tar.gz" \
    && curl --fail --show-error --location "$url" --output /tmp/trivy.tar.gz \
    && echo "$expected  /tmp/trivy.tar.gz" | sha256sum --check --strict \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && trivy --version \
    && rm -f /tmp/trivy.tar.gz \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10005 porygon \
    && useradd --uid 10005 --gid porygon --create-home --shell /usr/sbin/nologin porygon \
    && mkdir -p /var/lib/trivy \
    && chown -R porygon:porygon /var/lib/trivy /app

COPY pyproject.toml ./
COPY src ./src
COPY tests ./tests

RUN pip install --no-cache-dir ".[test]" \
    && chown -R porygon:porygon /app

USER 10005:10005
EXPOSE 8004
CMD ["uvicorn", "porygon_scanner.main:app", "--host", "0.0.0.0", "--port", "8004", "--no-access-log"]
