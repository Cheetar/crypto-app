FROM python:3
ENV PYTHONUNBUFFERED 1
RUN mkdir /code
WORKDIR /code
ADD requirements.txt /code/
RUN apt-get update
RUN apt-get -y install build-essential libcap-dev gcc
RUN apt-get -y install libgmp3-dev libmpfr-dev libmpfr4 mpc libmpc-dev
RUN pip install -r requirements.txt
ADD ./ /code/
