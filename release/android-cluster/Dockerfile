# Compile only in the cluster. Both base images and the Android vendor archives
# are pinned; the resulting OCI digest is part of the native input identity.
ARG RELEASE_BASE=127.0.0.1:30444/ghost/gchat-release@sha256:d1eab766f3826103c7c7734f58f44ca60f07abe1e1422f9cf49a14b9f1361c8a
FROM rust:1.98.1-bookworm@sha256:c49256cbe5ea0188bc658a689500d70c41eb51f009a7a7be209caf60a944f3ec AS rust
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

FROM runner AS builder
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev libclang-dev clang cmake ninja-build unzip zip curl zstd openjdk-21-jdk-headless adb zipalign && rm -rf /var/lib/apt/lists/*
COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:/opt/android/platform-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN rustup target add aarch64-linux-android x86_64-linux-android
COPY release/android-cluster/android-toolchain.py /opt/gcoms/android-toolchain.py
COPY release/android-cluster/android-packages.json /opt/gcoms/android-packages.json
RUN python3 /opt/gcoms/android-toolchain.py && mkdir -p /home/release/.android && chown -R 10001:10001 /usr/local/cargo /home/release/.android
ENV ANDROID_HOME=/opt/android ANDROID_SDK_ROOT=/opt/android ANDROID_NDK_HOME=/opt/android/ndk/27.3.13750724 JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
USER 10001
ENTRYPOINT ["python3", "/opt/gcoms/scripts/android_release_host.py"]
CMD ["build"]
