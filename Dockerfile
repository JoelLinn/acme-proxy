FROM rust:alpine as bob

RUN apk add --no-cache musl-dev

WORKDIR /usr/src/app

ADD Cargo.toml .
ADD src src

RUN rustc -V
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo install --target x86_64-unknown-linux-musl --root . --path .


FROM scratch

COPY --from=bob /usr/src/app/bin/acme-proxy /usr/local/bin/
COPY --from=bob /etc/passwd /etc/

EXPOSE 8080
USER nobody

# Regex to match valid domains, examples:
#  .*                                         any string/domain
#  ^intra\.example\.com$                      exactly intra.example.com
#  (\.i\.example\.com)$|(\.iana\.org)$        any subdomain under i.example.com or any subdomain under iana.org
ENV ACME_LEGAL_HOSTS .*
# Timeout for internal request in ms
ENV ACME_TIMEOUT 1000

CMD ["acme-proxy"]
