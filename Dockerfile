FROM ubuntu:latest as builder

RUN apt-get update

# Get Ubuntu packages
RUN apt-get update \
    && apt-get install -y \
      build-essential \
      curl clang protobuf-compiler

# Get Rust
RUN USER=root curl https://sh.rustup.rs -sSf | bash -s -- -y

RUN USER=root echo 'source $HOME/.cargo/env' >> $HOME/.bashrc
RUN USER=root ls -l $HOME/.cargo/bin/cargo

RUN USER=root $HOME/.cargo/bin/cargo new --bin secret_vault
WORKDIR ./secret_vault
COPY ./Cargo.toml ./Cargo.toml
ADD ./src ./src
ADD ./protos ./protos
ADD ./tls ./tls
ADD ./build.rs ./build.rs
ADD ./config.json ./config.json

RUN $HOME/.cargo/bin/cargo build --release
RUN rm ./target/release/deps/secret_vault*

FROM ubuntu:latest
ARG APP=/usr/src/secret_vault

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 32361

ENV TZ=Etc/UTC \
    APP_USER=root

RUN mkdir -p ${APP}
RUN mkdir -p ${APP}/tls
RUN mkdir -p /home/zulu/work/rust/secret_vault

COPY --from=builder /secret_vault/target/release/secret_vault ${APP}/secret_vault
COPY --from=builder /secret_vault/config.json ${APP}/config.json
COPY --from=builder /secret_vault/config.json /home/zulu/work/rust/secret_vault
COPY --from=builder /secret_vault/tls/server.key ${APP}/tls/
COPY --from=builder /secret_vault/tls/server.pem ${APP}/tls/
COPY --from=builder /secret_vault/tls/ca.pem ${APP}/tls/

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./secret_vault"]
