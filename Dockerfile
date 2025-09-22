FROM golang:1.22 AS build
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/compliance-agent

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /
COPY --from=build /out/compliance-agent /compliance-agent
USER nonroot:nonroot
ENTRYPOINT ["/compliance-agent"]

