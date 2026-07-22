FROM golang:1.23-alpine AS builder

WORKDIR /agent

COPY go.mod ./
COPY go.sum ./
COPY cmd /agent/cmd
COPY config /agent/config
RUN go mod download 
COPY main.go ./
RUN go build 

FROM debian:bookworm-slim

# Install OpenSSL 3 libraries and ca-certificates
RUN apt-get update && apt-get install -y sudo && apt-get install tpm2-tools -y

# Set the working directory inside the container
WORKDIR /agent

# Copy the binary built in the previous stage
COPY --from=builder /agent .

COPY docker_startup.sh ./
RUN mkdir sys
RUN chmod +x docker_startup.sh
CMD ["./docker_startup.sh"]