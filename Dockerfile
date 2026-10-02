FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 BABEL_DATA_DIR=/data
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
