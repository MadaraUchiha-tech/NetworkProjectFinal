FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      build-essential python3 valgrind >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /work
