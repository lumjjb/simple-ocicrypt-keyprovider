.PHONY: all

all: simple_crypt

simple_crypt:
	go build -o $@ .

clean:
	rm -f simple_crypt
