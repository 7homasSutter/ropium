
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
docker run --rm -it -v ./ropium/:/ropium/ ropium
cd /ropium/
make clean && make && make install

# Analyse a file with ROPium
(ropium)> load -a X86 /tmp/FILE

# Loading gadgets from a rp++ file
## Run rp++ with first to get the gadgets
rp-win.exe -f FILE -r 10 --print-bytes > out.txt

## Then load the gadgets in ROPium
(ropium)> load_rp out.txt
```