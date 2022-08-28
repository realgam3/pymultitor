FROM mitmproxy/mitmproxy:8.1.1

# Create app directory
WORKDIR /app

# Bundle app source
COPY requirements.txt /app/
RUN set -eux; \
    \
    apt-get update && apt-get install -y tor; \
    pip install -r requirements.txt

COPY pymultitor.py /app/

EXPOSE 8080

ENTRYPOINT [ "python3", "/app/pymultitor.py", "-lh", "0.0.0.0", "-lp", "8080" ]