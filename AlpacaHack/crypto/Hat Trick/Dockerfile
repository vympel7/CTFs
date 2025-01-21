FROM python:3-slim

WORKDIR /app

RUN pip install pycryptodome
RUN apt update -y && apt install -y socat

COPY server.py .

EXPOSE 9999

ENTRYPOINT ["/bin/sh", "-c"]

CMD ["socat -t 10 -T 60 -v TCP-LISTEN:9999,reuseaddr,fork EXEC:'python3 /app/server.py'"] 
