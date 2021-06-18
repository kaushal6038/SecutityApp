FROM python:2.7

WORKDIR /redtree

COPY . /redtree/

RUN pip install -r requirements.txt

ENV CURL_CA_BUNDLE=

RUN apt-get update \
    && apt-get install -y \
        curl \
        libxrender1 \
        libfontconfig \
        libxtst6 \
        xz-utils \
        apt-utils

RUN curl "https://downloads.wkhtmltopdf.org/0.12/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz" -L -o "wkhtmltopdf.tar.xz"

RUN tar Jxvf wkhtmltopdf.tar.xz

RUN mv wkhtmltox/bin/wkhtmltopdf /usr/local/bin/wkhtmltopdf

RUN chmod +x /redtree/rt_entrypoint.sh