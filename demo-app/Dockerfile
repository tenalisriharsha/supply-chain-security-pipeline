FROM python:3.12-slim

WORKDIR /app
COPY app.py .

EXPOSE 8080
USER 65534:65534

CMD ["python", "app.py"]
