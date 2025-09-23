FROM python:3.9-slim-bullseye

RUN pip install ROPgadget capstone prompt_toolkit lief

RUN apt-get update && apt-get install -y --no-install-recommends \
		g++ \
		libmagic1 \
        make \
        libcapstone-dev

COPY . ropium/

# RUN cd ropium && make && make test && make install

ENTRYPOINT ["/bin/bash"]
