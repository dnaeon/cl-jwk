FROM clfoundation/ecl:21.2.1

ENV QUICKLISP_ADD_TO_INIT_FILE=true
ENV QUICKLISP_DIST_VERSION=latest
ENV LISP=ecl

WORKDIR /app
COPY . .

# Use latest ironclad from Github, until it gets into Quicklisp
RUN mkdir -p ~/.config/common-lisp/source-registry.conf.d && \
    echo '(:tree "/app/")' >  ~/.config/common-lisp/source-registry.conf.d/workspace.conf && \
    git clone https://github.com/sharplispers/ironclad.git && \
    /usr/local/bin/install-quicklisp

ENTRYPOINT ["./scripts/run-tests.sh"]
