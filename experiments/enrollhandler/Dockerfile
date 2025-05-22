FROM golang:1.24 as builder

COPY . ./

RUN go build -o /server

FROM ubuntu:22.04

COPY --from=builder /server /server

CMD ["/server"]
