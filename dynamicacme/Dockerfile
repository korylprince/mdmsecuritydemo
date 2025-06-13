FROM golang:1.24 as builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN go build -o /server

FROM ubuntu:22.04

COPY --from=builder /server /server

CMD ["/server"]
