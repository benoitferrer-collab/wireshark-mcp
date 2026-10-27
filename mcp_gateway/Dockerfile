FROM python:3.12-slim
WORKDIR /gateway
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY mcp_gateway/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home gateway
COPY mcp_gateway ./mcp_gateway
USER gateway
EXPOSE 8001
CMD ["python", "-m", "mcp_gateway.server"]
