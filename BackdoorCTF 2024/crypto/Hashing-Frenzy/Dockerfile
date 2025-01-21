FROM python:3-slim

WORKDIR /app

RUN pip install pycryptodome
RUN apt update -y && apt install -y socat

COPY main.py .

ENV FLAG=flag{test}

EXPOSE 5050

ENTRYPOINT ["/bin/sh", "-c"]

CMD ["socat -t 10 -T 60 -v TCP-LISTEN:5050,reuseaddr,fork EXEC:/app/main.py"] 
