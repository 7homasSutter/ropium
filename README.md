
# About
**ROPium** (ex-ROPGenerator) is a library/tool that makes ROP-exploits easy. It automatically extracts and analyses gadgets from binaries and
lets you find ROP-chains with semantic queries. ROPium supports *X86* and *X64* architectures, soon to be 
extended with *ARM*.

# Docker

If needed you can run ROPium in a docker container. The container can be generated from the *Dockerfile* as
follows:

```bash
# Create your docker image (this will take time!)
docker build . --tag ropium

# Run the image in interactive mode, bind mounting the file to analyze
docker run --rm -it -v /FULL/HOST/PATH/FILE:/tmp/FILE:ro ropium

(ropium)> load -a X86 /tmp/FILE
```