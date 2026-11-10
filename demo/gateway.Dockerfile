# Lab image for the Access Governance Gateway. Builds apm from this fork's own
# src/apm_cli and installs the gateway's optional PDF/report dependency so the
# full lab (docker-compose) can run the gateway + render reports.
FROM python:3.11-slim

WORKDIR /app
COPY . /app

# Install the forked apm-cli (src/apm_cli) plus the reports extra. Build-time
# network is required here; this image is for the lab, not the offline sandbox.
RUN pip install --no-cache-dir -e ".[reports]"

EXPOSE 9090
# The streamable-HTTP MCP proxy entrypoint (see gateway/proxy.py serve()).
CMD ["python", "-c", "from gateway.proxy import serve; print('configure serve() with a Gateway in the lab')"]
