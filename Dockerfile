# artex-shield-proxy: the shield in front of any website.
#
#   docker build -t artex-shield-proxy .
#   docker run -p 8080:8080 -e ARTEX_SHIELD_BACKEND=http://your-site:80 artex-shield-proxy
#
# Every setting is an ARTEX_SHIELD_* variable; see README.md. To use a TOML
# file instead, mount it and set ARTEX_SHIELD_CONFIG=/etc/artex-shield.toml.
FROM python:3.13-slim

COPY pyproject.toml README.md LICENSE /tmp/artex-shield/
COPY src /tmp/artex-shield/src
RUN pip install --no-cache-dir /tmp/artex-shield && rm -rf /tmp/artex-shield

ENV ARTEX_SHIELD_LISTEN=0.0.0.0:8080 \
    PYTHONUNBUFFERED=1
USER nobody
EXPOSE 8080
# Checks the port the image listens on by default; change it with the listen setting.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8080), 3).close()"]
ENTRYPOINT ["artex-shield-proxy"]
