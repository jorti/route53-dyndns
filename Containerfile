ARG FEDORA_ARCH=x86_64
ARG FEDORA_VERSION=39
FROM registry.fedoraproject.org/fedora:${FEDORA_VERSION}-${FEDORA_ARCH}

RUN dnf update -y --setopt=install_weak_deps=False --nodocs && \
    dnf install -y --setopt=install_weak_deps=False --nodocs python3-boto3 python3-netifaces python3-pyyaml curl && \
    dnf clean all && \
    useradd -s /sbin/nologin -d / -c "Route 53 DynDNS updater" dyndns

COPY route53-dyndns.py /usr/local/bin/route53-dyndns.py
LABEL maintainer="Juan Orti Alcaine <jortialc@redhat.com>" \
      description="Route 53 DynDNS"
USER dyndns:dyndns
ENTRYPOINT ["/usr/local/bin/route53-dyndns.py"]
