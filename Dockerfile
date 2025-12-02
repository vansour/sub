FROM ghcr.io/vansour/rust:trixie AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# 编译发布版本
RUN cargo build --release && strip target/release/sub

FROM ghcr.io/vansour/debian:trixie-slim
# 安装运行时依赖 (curl for healthcheck, ca-certificates for https requests)
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends curl ca-certificates tzdata && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone

WORKDIR /app
# 创建数据目录
RUN mkdir -p /app/logs /app/data

COPY --from=builder /app/target/release/sub /app/sub
COPY web /app/web
# entrypoint 现在主要用于确保权限，不再需要复制默认 toml 文件
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV API=api
# 数据库文件将位于 /app/data/sub.db

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/bin/curl -f http://localhost:8080/healthz || exit 1

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/app/sub"]