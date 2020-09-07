FROM ekidd/rust-musl-builder:latest as bob

ADD --chown=rust:rust Cargo.toml .
ADD --chown=rust:rust src src

RUN rustc -V
RUN cargo install --path .


FROM alpine:latest

COPY --chown=root:root --from=bob /home/rust/.cargo/bin/acme-proxy /usr/local/bin/

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
