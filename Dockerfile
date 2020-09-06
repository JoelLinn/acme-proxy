FROM rust as bob

WORKDIR /usr/src/acme-proxy
COPY ./src ./src
COPY ./Cargo.toml .

RUN rustc -V
RUN cargo install --path .


FROM debian:buster-slim

COPY --from=bob /usr/local/cargo/bin/acme-proxy /usr/local/bin/acme-proxy

EXPOSE 8080
USER nobody

# Regex to match valid domains, examples:
#  .*                                         any string/domain
#  ^intra\.example\.com$                      exactly intra.example.com
#  (\.i\.example\.com)$|(\.iana\.org)$        any subdomain under i.example.com or any subdomain under iana.org
ENV ACME_DOMAINS .*
# Timeout for internal request in ms
ENV ACME_TIMEOUT 1000

CMD ["sh", "-c", "acme-proxy --legal_hosts=${ACME_DOMAINS} --timeout=${ACME_TIMEOUT}"]
