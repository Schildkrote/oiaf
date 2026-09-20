FROM golang:1.23 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /oiafd ./core/cmd/oiafd
RUN CGO_ENABLED=0 GOOS=linux go build -o /oiafctl ./cli/oiafctl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /oiafd /usr/local/bin/oiafd
COPY --from=builder /oiafctl /usr/local/bin/oiafctl
COPY ui/admin-console/ /ui/
EXPOSE 8080
USER nonroot
LABEL org.opencontainers.image.title="OIAF"
LABEL org.opencontainers.image.description="Open Identity Access Firewall"
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["/usr/local/bin/oiafd"]
