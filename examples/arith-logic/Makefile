.PHONY = all first

  RISCV64CC ?= riscv64-linux-gnu-gcc
   MIPS64CC ?= mips64-linux-gnuabi64-gcc
POWERPC64CC ?= powerpc64-linux-gnu-gcc
  AARCH64CC ?= aarch64-linux-gnu-gcc

RISCV64CFLAGS += -shared -fPIC
 MIPS64CFLAGS += -shared -fPIC
  PPC64CFLAGS += -shared -fPIC
AARCH64CFLAGS += -shared -fPIC

first: all

main-riscv64.so: main.c
	$(RISCV64CC) $(RISCV64CFLAGS) $< -o $@

main-mips64.so: main.c
	$(MIPS64CC) $(MIPS64CFLAGS) $< -o $@

main-powerpc64.so: main.c
	$(POWERPC64CC) $(POWERPC64CFLAGS) $< -o $@

main-powerpc64.so.fixup: main-powerpc64.so
	../../test-data/fixup.sh $< $@

main-aarch64.so: main.c
	$(AARCH64CC) $(AARCH64CFLAGS) $< -o $@

output-powerpc64: main-powerpc64.so main-powerpc64.so.fixup
	cargo build --release
	../../target/release/open-rns-analyzer -i $< -o $@ --fixup-file main-powerpc64.so.fixup calculate-dataflow

output-%: main-%.so
	cargo build --release
	../../target/release/open-rns-analyzer -i $< -o $@ calculate-dataflow

all: output-riscv64 output-mips64 output-aarch64 output-powerpc64

clean:
	rm -rf output-riscv64 output-mips64 output-powerpc64 main-riscv64.so main-mips64.so main-powerpc64.so main-powerpc64.so.fixup main-aarch64.so
