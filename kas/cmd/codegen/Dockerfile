# kaitai-struct-compile via docker
# Reference: https://github.com/blacktop/docker-kaitai/blob/master/Dockerfile
# And the 'install on ubuntu' instructions on https://kaitai.io
#
# Compile nanotdf.ksy:
#     docker build --tag ksc:0.8 --target compiler .
#     docker run -it --volume "$PWD":/workdir ksc:0.8 \
#       --target python \
#       --outdir build/gencode \
#       nanotdf.ksy
# Kaitai Struct IDE:
#     docker build --tag kside:0.8 --target ide .
#     docker run -p 8000:8000 kside:0.8
#
FROM openjdk:11-jre as compiler
RUN buildDeps='wget gnupg unzip git' \
    && apt-get update \
    && apt-get install -y $buildDeps python --no-install-recommends \
    && apt-key adv --keyserver hkp://pool.sks-keyservers.net --recv 379CE192D401AB61 \
    && echo "deb https://dl.bintray.com/kaitai-io/debian jessie main" \
    | tee /etc/apt/sources.list.d/kaitai.list \
    && apt-get update \
    && apt-get install -y kaitai-struct-compiler
WORKDIR /workdir
ENTRYPOINT ["/usr/bin/kaitai-struct-compiler"]

FROM compiler as ide
# TODO: Rebuild IDE so we can import nanoTDF def & samples
RUN git clone --depth 1 https://github.com/kaitai-io/ide-kaitai-io.github.io /kaitai/webide
WORKDIR /kaitai/webide
EXPOSE 8000
ENTRYPOINT ["/usr/bin/python"]
CMD ["-mSimpleHTTPServer"]
