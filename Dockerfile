# Use Miniconda as the base image
FROM continuumio/miniconda3:latest

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update apt-get and install required packages
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    wget \
    build-essential \
    libxext6 \
    libxrender1 \
    libxtst6 \
    libx11-dev \
    make \
    binutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install OpenJDK 11 using wget
RUN wget https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.21%2B9/OpenJDK11U-jdk_x64_linux_hotspot_11.0.21_9.tar.gz && \
    tar -xvf OpenJDK11U-jdk_x64_linux_hotspot_11.0.21_9.tar.gz -C /opt/ && \
    rm OpenJDK11U-jdk_x64_linux_hotspot_11.0.21_9.tar.gz

# Configure update-alternatives for Java and Javac
RUN update-alternatives --install /usr/bin/java java /opt/jdk-11.0.21+9/bin/java 1 && \
    update-alternatives --install /usr/bin/javac javac /opt/jdk-11.0.21+9/bin/javac 1

# Set environment variables for Java
ENV JAVA_HOME=/opt/jdk-11.0.21+9
ENV PATH="$JAVA_HOME/bin:$PATH"

# Set the working directory inside the container
WORKDIR /app

# Copy the rest of the application code into the container
COPY . .

# Create the Conda environment using the environment.yml file
RUN conda env create -f environment.yml

# Ensure that bash starts with the conda environment activated
RUN echo "source activate header_md_3.11" >> ~/.bashrc

# Set the entrypoint to bash with interactive options
ENTRYPOINT ["/bin/bash"]

# Default to running bash in interactive mode
CMD ["-i"]