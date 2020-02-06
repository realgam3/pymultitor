FROM mitmproxy/mitmproxy:5.0.1

# Create app directory
WORKDIR /app


# Bundle app source
COPY pymultitor.py requirements.txt /app/

RUN apk update && apk add tor
RUN pip install -r requirements.txt

EXPOSE 8080

ENTRYPOINT [ "python3", "/app/pymultitor.py", "-lh", "0.0.0.0", "-lp", "8080" ]