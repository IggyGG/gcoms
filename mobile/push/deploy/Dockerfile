FROM docker.io/library/python@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY mobile/push/deploy/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes -r /app/requirements.lock
COPY mobile/push/gateway/gateway.py mobile/push/gateway/providers.py mobile/push/gateway/server.py /app/
COPY mobile/push/deploy/launcher.py mobile/push/deploy/health.py mobile/push/deploy/prepare.py /app/
USER 10001:10001
ENTRYPOINT ["python3", "/app/launcher.py"]
COPY mobile/push/deploy/runtime-sources.json /app/runtime-sources.json
RUN python3 -c 'import hashlib,json,pathlib; manifest=json.load(open("/app/runtime-sources.json")); assert all(hashlib.sha256(pathlib.Path("/app",p).read_bytes()).hexdigest()==h for p,h in manifest["files"].items())'
