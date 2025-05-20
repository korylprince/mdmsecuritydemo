FROM golang:1.24 as builder

COPY . ./

RUN go build -o /server

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    curl \
    net-tools \
    dnsutils \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /server /server

CMD ["/server"]
