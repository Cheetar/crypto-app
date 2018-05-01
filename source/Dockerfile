FROM python:3
ENV PYTHONUNBUFFERED 1
RUN mkdir /code
WORKDIR /code
ADD requirements.txt /code/
RUN apt-get update
RUN yes | apt-get install build-essential libcap-dev
RUN pip install -r requirements.txt
ADD ./ /code/

