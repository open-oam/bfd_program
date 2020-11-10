all:
	clang -O2 -target bpf -c xdp.c -o xdp.elf
