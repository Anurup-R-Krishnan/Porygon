# Porygon installation guide

Use a Linux machine with Docker Engine, Docker Compose v2, Git, Python 3.11 or later, Make and curl. Falco requires host kernel eBPF support. The recorded demonstration used kernel 7.2.7-1-cachyos and the pinned Falco 0.45.1 image in compose.yaml.

```sh
git clone https://github.com/Anurup-R-Krishnan/Porygon.git
cd Porygon
git checkout technical-enrichment
make init
make config
make up
make ps
curl --fail http://localhost:8000/health/ready
```

`make init` creates `.env` with separate generated internal and operator credentials and the Docker socket group. Preserve these credentials locally. The default response execution mode is disabled. Docker Compose builds the backend, collector, telemetry adapter, responder and scanner, and starts their dependencies. The Compose file records pinned external images and service configuration.

Run `make verify-static` and `make verify-unit` for source checks. Run `bash scripts/verify_infrastructure.sh` for stack readiness. The demonstration instructions describe the complete controlled workflow and offline reproduction of its recorded outputs.

Stop the stack with `make down`. Existing database and spool volumes are retained for subsequent runs.
