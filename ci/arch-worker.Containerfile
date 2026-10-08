FROM archlinux@sha256:8745817f349ed24373341ddb92776209eeec3f0364ea48f7f645ac5800d30a50

COPY ci/arch-worker-pacman.conf /etc/pacman-phase6.conf

RUN pacman --config /etc/pacman-phase6.conf -Syyuu --noconfirm \
    && pacman --config /etc/pacman-phase6.conf -S --noconfirm --needed \
      archiso=90-1 \
      edk2-ovmf=202608-1 \
      git=2.55.0-1 \
      gnupg=2.4.9-3 \
      openssh=10.5p1-1 \
      parted=3.8-1 \
      python=3.14.7-1 \
      qemu-desktop=11.1.1-4 \
      shellcheck=0.11.0-139

COPY tools/__init__.py tools/kitpro_repo.py tools/worker_manifest.py /usr/local/lib/kitpro-worker/tools/
COPY ci/worker-lock.json /usr/share/kitpro-worker/worker-lock.json

RUN PYTHONPATH=/usr/local/lib/kitpro-worker \
      python -m tools.worker_manifest verify-lock /usr/share/kitpro-worker/worker-lock.json \
    && pacman -Scc --noconfirm

ENV LANG=C.UTF-8
ENV PYTHONPATH=/usr/local/lib/kitpro-worker
ENV KITPRO_WORKER_LOCK=/usr/share/kitpro-worker/worker-lock.json
WORKDIR /workspace
