all: kuz

kuz: ./src/kuz_ctr_calc.c
	@echo "Compiling..."
	@gcc ./main.c ./src/kuz_ctr_calc.c -o output.o
	@./output.o
	@echo "[MD5] in.txt: input file (not encrpyted), out.txt: output file (decrypted)"
	@md5sum ./in.txt
	@md5sum ./out.txt

clean:
	@echo "Cleaning..."
	@rm -f ./in_enc.txt ./out.txt
