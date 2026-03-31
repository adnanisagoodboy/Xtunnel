FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY . .

RUN go build -o xtunnel-server .

# ---

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/xtunnel-server .

EXPOSE 8080

CMD ["./xtunnel-server"]
