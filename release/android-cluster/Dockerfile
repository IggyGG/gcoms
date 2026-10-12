# Compile only in the cluster. Both base images and the Android vendor archives
# are pinned; the resulting OCI digest is part of the native input identity.
ARG RELEASE_BASE=127.0.0.1:30444/ghost/gchat-release@sha256:d1eab766f3826103c7c7734f58f44ca60f07abe1e1422f9cf49a14b9f1361c8a
ARG ANDROID_TOOLCHAIN_BASE=127.0.0.1:30444/ghost/android-builder@sha256:364f386a26a8308f7f8bf1ba9997d294abbbfc764e1eee1a10be5cbe0f97b941
FROM ${RELEASE_BASE} AS runner
USER root
COPY release/android-cluster/requirements.lock /opt/gcoms/requirements.lock
RUN python3 -m pip install --break-system-packages --no-cache-dir -r /opt/gcoms/requirements.lock
COPY scripts/android_release*.py scripts/android_release*.sh /opt/gcoms/scripts/
RUN chmod 755 /opt/gcoms/scripts/android_release_git_askpass.py
USER 10001
ENTRYPOINT ["python3", "/opt/gcoms/scripts/android_release_cluster.py"]
CMD ["--config", "/config/android-agent.json", "tick"]

# The existing coordinator gains the optional Android lane. Supply the exact
# source-bound GChat files under gchat/ in the context; never copy host state.
FROM runner AS coordinator
COPY gchat/scripts/release_coordinator.py gchat/scripts/release_android_agent.py /opt/gchat/scripts/
ARG GCHAT_CONTROLLER_REVISION
ENV GCHAT_CONTROLLER_REVISION=$GCHAT_CONTROLLER_REVISION
ENTRYPOINT ["python3", "/opt/gchat/automation/start"]
CMD ["--state", "/state", "--config", "/config/controller.json"]

# A release-code edit must never reinstall Rust, Java or Android packages.
# Refresh the pinned base separately with Dockerfile.toolchain when those
# inputs change; the native input identity includes the resulting image digest.
FROM ${ANDROID_TOOLCHAIN_BASE} AS builder
USER root
RUN chmod 644 /opt/android/cmake/3.22.1/source.properties
COPY scripts/android_release*.py scripts/android_release*.sh /opt/gcoms/scripts/
USER 10001
ENTRYPOINT ["python3", "/opt/gcoms/scripts/android_release_host.py"]
CMD ["build"]
