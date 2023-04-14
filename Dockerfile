# Use the official Rust image as the base image
FROM rust:latest

# Set the working directory to /app
WORKDIR /app

# Copy the project files into the container
COPY . .

# Install radare2 dependencies
RUN apt-get update && \
    apt-get install -y git build-essential pkg-config cmake zlib1g-dev libglib2.0-dev


# Download and build radare2
RUN git clone --branch 5.6.0 --depth 1 https://github.com/radareorg/radare2.git && \
    cd radare2 && \
    sys/install.sh

# Set the environment variable to use the radare2 binary
ENV PATH="/app/radare2/bin:${PATH}"

# Build the project
RUN cargo build --release

# Set the entrypoint to the CLI binary
ENTRYPOINT ["/app/target/release/open-rns-analyzer"]
