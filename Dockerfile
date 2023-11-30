FROM alpine:3.18
LABEL maintainer="th@taaa.eu"
RUN apk add --update --no-cache python3 py3-pip
RUN mkdir /mdns
COPY . /ddnsm
RUN poetry install 
RUN chmod a+x /ddnsm/ddnsmapi/__init__.py
WORKDIR /dnsm
ENTRYPOINT ["/ddnsm/ddnsmapi/__init__.py"]
