FROM python:2.7

WORKDIR /purpleleaf

COPY . /purpleleaf/

RUN apt-get update -y

RUN apt-get install -y \
  libev-dev

RUN pip install -r requirements.txt

# Uninstall build-base now that we're done

RUN chmod +x /purpleleaf/pl_entrypoint.sh
