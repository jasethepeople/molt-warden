FROM --platform=linux/amd64 python:3.12-slim-bookworm@sha256:0f086103b026048cc50cb5da25ec435c023c5241a83fc44daea593377abc61c4
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY docker/runner.py /opt/warden/runner.py
USER 65534:65534
ENTRYPOINT ["python3", "/opt/warden/runner.py"]
