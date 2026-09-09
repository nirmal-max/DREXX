# AKHANDA, verifier and recovery image.
#
# SCOPE, AND IT IS DELIBERATELY NARROW. This container runs the parts of AKHANDA that are
# pure computation over bytes you hand it:
#
#     VERIFY   a chain someone gives you, in Python and in Rust, with no network
#     CARVE    a disk image into artefacts
#     CERTIFY  produce the NIST + BSA certificate from a chain
#     TEST     the full suite, so "it passes on my machine" stops being the claim
#
# IT DOES NOT ERASE DEVICES AND IT DOES NOT RUN THE WITNESS. Both are refused by design,
# not by omission. See DOCKER.md for why -- in short, a container shares the host kernel,
# so a containerised witness is not a second principal, and a containerised device wipe is
# a privileged write to the host's hardware wearing the costume of a sandbox.
#
#   docker build -t akhanda .
#   docker run --rm -v "$PWD/evidence:/work" akhanda verify /work/chain.json
#
FROM rust:1.83-slim-bookworm AS rustbuild
WORKDIR /build
COPY rust/akhanda-verify/ ./akhanda-verify/
WORKDIR /build/akhanda-verify
RUN cargo build --release --locked || cargo build --release

# ---------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm

# The verifier must run somewhere it cannot quietly acquire privilege. No sudo, no
# build toolchain, no package manager left behind for an attacker who lands here.
RUN useradd --create-home --uid 10001 akhanda

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY tests/ ./tests/
COPY scripts/ ./scripts/
COPY console/ ./console/
COPY pytest.ini README.md docs/ENGINEERING_RULES.md ./
COPY --from=rustbuild /build/akhanda-verify/target/release/akhanda-verify /usr/local/bin/

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && chown -R akhanda:akhanda /app

USER akhanda
ENV PYTHONPATH=/app/src AKHANDA_HOME=/home/akhanda/.akhanda PYTHONDONTWRITEBYTECODE=1
WORKDIR /work

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["help"]
