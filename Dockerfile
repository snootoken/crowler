# Use latest Python Alpine image
FROM python:3.12.8-alpine3.20

LABEL maintainer="https://github.com/prowler-cloud/prowler"

# Update system dependencies and install essential tools
RUN apk --no-cache upgrade && apk --no-cache add curl git

# Create non-root user
RUN mkdir -p /home/prowler && \
    echo 'prowler:x:1000:1000:prowler:/home/prowler:' > /etc/passwd && \
    echo 'prowler:x:1000:' > /etc/group && \
    chown -R prowler:prowler /home/prowler

# Set up environment
USER prowler
WORKDIR /home/prowler

# Copy necessary files
COPY prowler/ /home/prowler/prowler/
COPY dashboard/ /home/prowler/dashboard/
COPY pyproject.toml /home/prowler
COPY README.md /home/prowler

# Install Python dependencies
ENV HOME='/home/prowler'
ENV PATH="$HOME/.local/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir flask

# Remove deprecated dash dependencies
RUN pip uninstall dash-html-components -y && \
    pip uninstall dash-core-components -y

# Ensure Render assigns a port dynamically
ENV PORT=8080
EXPOSE 8080

# Create a simple HTTP server
COPY <<EOF /home/prowler/server.py
from flask import Flask
app = Flask(__name__)
@app.route('/')
def home():
    return "Prowler Running"
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(8080))
EOF

# Start the HTTP server to keep the container running
CMD ["python", "/home/prowler/server.py"]
