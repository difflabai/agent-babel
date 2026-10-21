FROM python:3.13-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 BABEL_DATA_DIR=/data \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs PIP_CERT=/etc/ssl/certs/ca-certificates.crt
# Signed distro metadata bootstraps trust before any HTTPS package downloads.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge 20250419+deb13u1 \
    && update-ca-certificates && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 babel && useradd --uid 10001 --gid babel --no-create-home babel \
    && mkdir /data /app && chown babel:babel /data
WORKDIR /app
COPY --chown=babel:babel babel/ babel/
COPY --chown=babel:babel web/ web/
COPY --chown=babel:babel mcp_server.py ./
USER 10001:10001
EXPOSE 8080 8765
ENTRYPOINT ["python", "-m", "babel"]
CMD ["serve", "--container"]
