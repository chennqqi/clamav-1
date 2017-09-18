FROM ffg/malice

LABEL maintainer "https://github.com/chennqqi"

LABEL malice.plugin.repository = "https://github.com/chennqqi/clamav-docker.git"
LABEL malice.plugin.category="av"
LABEL malice.plugin.mime="*"
LABEL malice.plugin.docker.engine="*"


COPY . /go/src/github.com/chennqqi/clamav-docker

RUN apk --update add --no-cache clamav clamav-dev ca-certificates \
  && echo "Building avscan Go binary..." \
  && cd /go/src/golang.org/x/ \
  && git clone https://github.com/golang/crypto \
  && git clone https://github.com/golang/sys \
  && cd /go/src/github.com/chennqqi/clamav-docker \
  && export GOPATH=/go \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/avscan \
  && rm -rf /go /usr/local/go /usr/lib/go /tmp/* \
  && apk del --purge .build-deps

# Update ClamAV Definitions
RUN mkdir -p /opt/malice \
  && chown malice /opt/malice \
  && avscan update

# Add EICAR Test Virus File to malware folder
ADD http://www.eicar.org/download/eicar.com.txt /malware/EICAR

RUN chown malice -R /malware

WORKDIR /malware

CMD ["avscan"]
#ENTRYPOINT ["avscan"]
# ENTRYPOINT ["su-exec","malice","/sbin/tini","--","avscan"]
CMD ["--help"]
