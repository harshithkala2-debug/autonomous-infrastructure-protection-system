FROM python:3.12-slim

RUN useradd --create-home --uid 10001 aips
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY aips ./aips
RUN pip install --no-cache-dir ".[crypto]"

USER aips
ENV PYTHONUNBUFFERED=1
EXPOSE 8780

# Mount your configuration at /config and provide secrets via environment variables.
#   docker run -v $PWD/examples:/config -e AIPS_API_TOKEN=... -e AIPS_BACKUP_HMAC=... aips
ENTRYPOINT ["aips"]
CMD ["run", "--config", "/config/aips.toml"]
