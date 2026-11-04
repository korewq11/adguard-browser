FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m playwright install --with-deps chromium --only-shell \
    && useradd --create-home --uid 10001 browser \
    && chmod -R a+rX /ms-playwright
COPY service.py index.html ui.js ui.css ./
USER browser
EXPOSE 10000
CMD ["python", "-u", "service.py"]
