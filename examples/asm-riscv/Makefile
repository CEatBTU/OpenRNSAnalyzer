.PHONY: clean all first

RISCV64AS ?= riscv64-linux-gnu-as

first: all

main.o: main.S
	$(RISCV64AS) $< -o $@

output: main.o
	cargo build --release
	../../target/release/open-rns-analyzer -i $< -o $@ calculate-dataflow

clean:
	rm -rf output main.o main.so

all: output
