FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gdb \
    make \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY .git ./
COPY Makefile ./
COPY src ./src
COPY tests ./tests
COPY include ./include

RUN make clean test 

CMD ["make", "test"]