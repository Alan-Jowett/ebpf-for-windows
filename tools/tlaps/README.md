# TLAPS (tlapm) in Docker

This folder provides a Docker image you can use to run TLAPS locally in a Linux environment.

## Build

From the repo root:

```bash
docker build -t ebpfw-tlaps -f tools/tlaps/Dockerfile .
```

## Run proofs

From the repo root (mounts your working tree into the container at `/repo`):

```bash
docker run --rm -t -v "${PWD}:/repo" -w /repo ebpfw-tlaps
```

This runs `scripts/run_tlaps.sh`, which by convention checks any proof modules matching `models/**/*Proof*.tla`.

## Run a single module

```bash
docker run --rm -t -v "${PWD}:/repo" -w /repo ebpfw-tlaps tlapm --cleanfp models/epoch/EpochModelProofs.tla
```
