FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATABASE_PATH=/data/nexus.db
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home nexus && mkdir /data && chown nexus:nexus /data
COPY --chown=nexus:nexus app.py directory.py deployment.py wsgi.py ./
COPY --chown=nexus:nexus static ./static
COPY --chown=nexus:nexus collectors ./collectors
COPY --chown=nexus:nexus deployment ./deployment
COPY --chown=nexus:nexus docs/AUTOMATIC_ROLLOUT.md ./docs/AUTOMATIC_ROLLOUT.md
USER nexus
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--timeout", "60", "wsgi:application"]
