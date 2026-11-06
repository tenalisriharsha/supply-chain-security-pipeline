FROM python:3.12-slim

# Pick up any OS security patches released after this base image was built
# (e.g. apt/libapt-pkg point releases), so the shipped image doesn't carry
# fixable CVEs that are only stale because of image build timing.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py .

EXPOSE 8080
USER 65534:65534

CMD ["python", "app.py"]
