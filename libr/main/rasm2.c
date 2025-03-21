/* radare - LGPL - Copyright 2009-2022 - pancake, nibble, maijin */

#define R_LOG_ORIGIN "rasm2"

#include <r_anal.h>
#include <r_asm.h>
#include <r_lib.h>
#include <r_main.h>

typedef struct {
	RLib *l;
	RAsm *a;
	RAnal *anal;
	bool oneliner;
	bool coutput;
	bool json;
	bool quiet;
} RAsmState;

static void __load_plugins(RAsmState *as);

static void __as_set_archbits(RAsmState *as) {
	r_asm_use (as->a, R_SYS_ARCH);
	r_anal_use (as->anal, R_SYS_ARCH);
	int sysbits = (R_SYS_BITS & R_SYS_BITS_64)? 64: 32;
	r_asm_set_bits (as->a, sysbits);
	r_anal_set_bits (as->anal, sysbits);
}

static RAsmState *__as_new(void) {
	RAsmState *as = R_NEW0 (RAsmState);
	if (as) {
		as->l = r_lib_new (NULL, NULL);
		as->a = r_asm_new ();
		as->anal = r_anal_new ();
		r_unref (as->anal->config);
		as->a->num = r_num_new (NULL, NULL, NULL);
		as->anal->config = r_ref_ptr (as->a->config);
		r_anal_bind (as->anal, &as->a->analb);
		__load_plugins (as);
		__as_set_archbits (as);
	}
	return as;
}

static void __as_free(RAsmState *as) {
	if (as) {
		if (as->a) {
			r_num_free (as->a->num);
		}
		r_asm_free (as->a);
		r_anal_free (as->anal);
		r_lib_free (as->l);
		free (as);
	}
}

static char *stackop2str(int type) {
	switch (type) {
	case R_ANAL_STACK_NULL: return strdup ("null");
	case R_ANAL_STACK_NOP: return strdup ("nop");
	//case R_ANAL_STACK_INCSTACK: return strdup ("incstack");
	case R_ANAL_STACK_GET: return strdup ("get");
	case R_ANAL_STACK_SET: return strdup ("set");
	}
	return strdup ("unknown");
}

static int showanal(RAsmState *as, RAnalOp *op, ut64 offset, ut8 *buf, int len, PJ *pj) {
	int ret = r_anal_op (as->anal, op, offset, buf, len, R_ARCH_OP_MASK_ESIL);
	if (ret < 1) {
		return ret;
	}
	char *stackop = stackop2str (op->stackop);
	const char *optype = r_anal_optype_tostring (op->type);
	char *bytes = r_hex_bin2strdup (buf, ret);
	if (as->json) {
		pj_o (pj);
		pj_kn (pj, "opcode", offset);
		pj_ks (pj, "bytes", bytes);
		pj_ks (pj, "type", optype);
		if (op->jump != UT64_MAX) {
			pj_kn (pj, "jump", op->jump);
		}
		if (op->fail != UT64_MAX) {
			pj_kn (pj, "fail", op->fail);
		}
		if (op->val != UT64_MAX) {
			pj_kn (pj, "val", op->val);
		}
		if (op->ptr != UT64_MAX) {
			pj_kn (pj, "ptr", op->ptr);
		}
		pj_ks (pj, "stackop", stackop);
		pj_ks (pj, "esil", r_strbuf_get (&op->esil));
		pj_kn (pj, "stackptr", op->stackptr);
		pj_end (pj);
	} else {
		printf ("offset:   0x%08" PFMT64x "\n", offset);
		printf ("bytes:    %s\n", bytes);
		printf ("type:     %s\n", optype);
		if (op->jump != -1LL) {
			printf ("jump:     0x%08" PFMT64x "\n", op->jump);
		}
		if (op->fail != -1LL) {
			printf ("fail:     0x%08" PFMT64x "\n", op->fail);
		}
		//if (op->ref != -1LL)
		//      printf ("ref:      0x%08"PFMT64x"\n", op->ref);
		if (op->val != -1LL) {
			printf ("value:    0x%08" PFMT64x "\n", op->val);
		}
		printf ("stackop:  %s\n", stackop);
		printf ("esil:     %s\n", r_strbuf_get (&op->esil));
		printf ("stackptr: %" PFMT64d "\n", op->stackptr);
		// produces (null) printf ("decode str: %s\n", r_anal_op_tostring (anal, op));
		printf ("\n");
	}
	free (stackop);
	free (bytes);
	return ret;
}

// TODO: add israw/len
static int show_analinfo(RAsmState *as, const char *arg, ut64 offset) {
	ut8 *buf = (ut8 *)strdup ((const char *)arg);
	int ret, len = r_hex_str2bin ((char *)buf, buf);
	PJ *pj = pj_new ();
	if (!pj) {
		free (buf);
		return 0;
	}
	RAnalOp aop = {0};
	if (as->json) {
		pj_a (pj);
	}
	for (ret = 0; ret < len;) {
		aop.size = 0;
		if (r_anal_op (as->anal, &aop, offset, buf + ret, len - ret, R_ARCH_OP_MASK_BASIC) < 1) {
			R_LOG_ERROR ("instruction analysis failed at 0x%08"PFMT64x, offset);
			break;
		}
		if (aop.size < 1) {
			if (as->json) {
				pj_o (pj);
				pj_ks (pj, "bytes",  r_hex_bin2strdup (buf, ret));
				pj_ks (pj, "type", "Invalid");
				pj_end (pj);
			} else {
				R_LOG_ERROR ("Invalid");
			}
			break;
		}
		showanal (as, &aop, offset, buf + ret, len - ret, pj);
		ret += aop.size;
		r_anal_op_fini (&aop);
	}
	if (as->json) {
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	free (buf);
	return ret;
}

static const char *has_esil(RAsmState *as, const char *name) {
	if (as && name) {
		RListIter *iter;
		RAnalPlugin *h;
		r_list_foreach (as->anal->plugins, iter, h) {
			if (h->name && !strcmp (name, h->name)) {
				return h->esil? "Ae": "A_";
			}
		}
	}
	return "__";
}

static void rarch2_list(RAsmState *as, const char *arch) {
	char bits[32];
	RArchPlugin *h;
	RListIter *iter;
	const char *feat2, *feat;
	PJ *pj = NULL;
	if (as->json) {
		pj = pj_new ();
		pj_a (pj);
	}
	r_list_foreach (as->anal->arch->plugins, iter, h) {
		feat = "_d";
		feat2 = "e";
		bits[0] = 0;
		if (h->bits == 27) {
			strcat (bits, "27");
		} else if (h->bits == 0) {
			strcat (bits, "any");
		} else {
			if (h->bits & 4) {
				strcat (bits, "4 ");
			}
			if (h->bits & 8) {
				strcat (bits, "8 ");
			}
			if (h->bits & 16) {
				strcat (bits, "16 ");
			}
			if (h->bits & 32) {
				strcat (bits, "32 ");
			}
			if (h->bits & 64) {
				strcat (bits, "64 ");
			}
		}
		if (as->quiet) {
			printf ("%s\n", h->name);
		} else if (as->json) {
			pj_o (pj);
			pj_ks (pj, "name", h->name);
			pj_k (pj, "bits");
			pj_a (pj);
			pj_i (pj, 32);
			pj_i (pj, 64);
			pj_end (pj);
			pj_ks (pj, "license", r_str_get_fail (h->license, "unknown"));
			pj_ks (pj, "description", h->desc);
			pj_ks (pj, "features", feat);
			pj_end (pj);
		} else {
			printf ("%s%s %-11s %-11s %-7s %s",
					feat, feat2, bits, h->name,
					r_str_get_fail (h->license, "unknown"), h->desc);
			if (h->author) {
				printf (" (by %s)", h->author);
			}
			if (h->version) {
				printf (" v%s", h->version);
			}
			printf ("\n");
		}
	}
	if (as->json) {
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
	}
}

static void ranal2_list(RAsmState *as, const char *arch) {
	char bits[32];
	RAnalPlugin *h;
	RListIter *iter;
	PJ *pj = NULL;
	if (as->json) {
		pj = pj_new ();
		pj_a (pj);
	}
	r_list_foreach (as->anal->plugins, iter, h) {
		bits[0] = 0;
		if (h->bits == 27) {
			strcat (bits, "27");
		} else if (h->bits == 0) {
			strcat (bits, "any");
		} else {
			if (h->bits & 4) {
				strcat (bits, "4 ");
			}
			if (h->bits & 8) {
				strcat (bits, "8 ");
			}
			if (h->bits & 16) {
				strcat (bits, "16 ");
			}
			if (h->bits & 32) {
				strcat (bits, "32 ");
			}
			if (h->bits & 64) {
				strcat (bits, "64 ");
			}
		}
		const char *feat = h->opasm? "ad": "_d";
		const char *feat2 = has_esil (as, h->name);
		if (as->quiet) {
			printf ("%s\n", h->name);
		} else if (as->json) {
			pj_o (pj);
			pj_ks (pj, "name", h->name);
			pj_k (pj, "bits");
			pj_a (pj);
			pj_i (pj, 32);
			pj_i (pj, 64);
			pj_end (pj);
			pj_ks (pj, "license", r_str_get_fail (h->license, "unknown"));
			pj_ks (pj, "description", h->desc);
			pj_ks (pj, "features", feat);
			pj_end (pj);
		} else {
			printf ("%s%s %-11s %-11s %-7s %s",
					feat, feat2, bits, h->name,
					r_str_get_fail (h->license, "unknown"), h->desc);
			if (h->author) {
				printf (" (by %s)", h->author);
			}
			if (h->version) {
				printf (" v%s", h->version);
			}
			printf ("\n");
		}
	}
	if (as->json) {
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
	}
	pj_free (pj);
}

static void rasm2_list(RAsmState *as, const char *arch) {
	int i;
	char bits[32];
	const char *feat2, *feat;
	RAsmPlugin *h;
	RListIter *iter;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	if (as->json) {
		pj_a (pj);
	}
	r_list_foreach (as->a->plugins, iter, h) {
		if (arch) {
			if (h->cpus && !strcmp (arch, h->name)) {
				char *c = strdup (h->cpus);
				int n = r_str_split (c, ',');
				for (i = 0; i < n; i++) {
					printf ("%s\n", r_str_word_get0 (c, i));
				}
				free (c);
				break;
			}
		} else {
			bits[0] = 0;
			if (h->bits == 27) {
				strcat (bits, "27");
			} else if (h->bits == 0) {
				strcat (bits, "any");
			} else {
				if (h->bits & 4) {
					strcat (bits, "4 ");
				}
				if (h->bits & 8) {
					strcat (bits, "8 ");
				}
				if (h->bits & 16) {
					strcat (bits, "16 ");
				}
				if (h->bits & 32) {
					strcat (bits, "32 ");
				}
				if (h->bits & 64) {
					strcat (bits, "64 ");
				}
			}
			feat = "__";
			if (h->assemble && h->disassemble) {
				feat = "ad";
			}
			if (h->assemble && !h->disassemble) {
				feat = "a_";
			}
			if (!h->assemble && h->disassemble) {
				feat = "_d";
			}
			feat2 = has_esil (as, h->name);
			if (as->quiet) {
				printf ("%s\n", h->name);
			} else if (as->json) {
				pj_o (pj);
				pj_ks (pj, "name", h->name);
				pj_k (pj, "bits");
				pj_a (pj);
				pj_i (pj, 32);
				pj_i (pj, 64);
				pj_end (pj);
				pj_ks (pj, "license", r_str_get_fail (h->license, "unknown"));
				pj_ks (pj, "description", h->desc);
				pj_ks (pj, "features", feat);
				pj_end (pj);
			} else {
				printf ("%s%s %-11s %-11s %-7s %s",
					feat, feat2, bits, h->name,
					r_str_get_fail (h->license, "unknown"), h->desc);
				if (h->author) {
					printf (" (by %s)", h->author);
				}
				if (h->version) {
					printf (" v%s", h->version);
				}
				printf ("\n");
			}
		}
	}
	if (as->json) {
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

static int rasm_show_help(int v) {
	if (v < 2) {
		printf ("Usage: rasm2 [-ACdDehLBvw] [-a arch] [-b bits] [-o addr] [-s syntax]\n"
			"             [-f file] [-F fil:ter] [-i skip] [-l len] 'code'|hex|0101b|-\n");
	}
	if (v != 1) {
		printf (" -a [arch]    set architecture to assemble/disassemble (see -L)\n"
			" -A           show Analysis information from given hexpairs\n"
			" -b [bits]    set cpu register size (8, 16, 32, 64) (RASM2_BITS)\n"
			" -B           binary input/output (-l is mandatory for binary input)\n"
			" -c [cpu]     select specific CPU (depends on arch)\n"
			" -C           output in C format\n"
			" -d, -D       disassemble from hexpair bytes (-D show hexpairs)\n"
			" -e           use big endian instead of little endian\n"
			" -E           display ESIL expression (same input as in -d)\n"
			" -f [file]    read data from file\n"
			" -F [in:out]  specify input and/or output filters (att2intel, x86.pseudo, ...)\n"
			" -h, -hh      show this help, -hh for long\n"
			" -i [len]     ignore/skip N bytes of the input buffer\n"
			" -j           output in json format\n"
			" -k [kernel]  select operating system (linux, windows, darwin, ..)\n"
			" -l [len]     input/Output length\n"
			" -L           list RAsm plugins: (a=asm, d=disasm, A=analyze, e=ESIL)\n"
			" -LL          list RAnal plugins (see anal.arch=?) combines with -j\n"
			" -LLL         list RArch plugins (see arch.arch=?) combines with -j\n"
			" -o,-@ [addr] set start address for code (default 0)\n"
			" -O [file]    output file name (rasm2 -Bf a.asm -O a)\n"
			" -p           run SPP over input for assembly\n"
			" -q           quiet mode\n"
			" -r           output in radare commands\n"
			" -s [syntax]  select syntax (intel, att)\n"
			" -v           show version information\n"
			" -x           use hex dwords instead of hex pairs when assembling.\n"
			" -w           what's this instruction for? describe opcode\n"
			" If '-l' value is greater than output length, output is padded with nops\n"
			" If the last argument is '-' reads from stdin\n");
		printf ("Environment:\n"
			" RASM2_NOPLUGINS   do not load shared plugins (speedup loading)\n"
			" RASM2_ARCH        same as rasm2 -a\n"
			" RASM2_BITS        same as rasm2 -b\n"
			" R2_LOG_LEVEL=X    change the log level\n"
			" R2_DEBUG          if defined, show error messages and crash signal\n"
			" R2_DEBUG_ASSERT=1 lldb -- r2 to get proper backtrace of the runtime assert\n"
			"");
	}
	if (v == 2) {
		printf ("Preprocessor directives:\n");
		r_asm_list_directives ();
		printf ("Assembler directives:\n");
		printf (".intel_syntax\n"
			".att_syntax     sets e asm.syntax=att to use AT&T syntax parser\n"
			".endian [0,1]   default endian is system endian, 0=little, 1=big\n"
			".big_endian     call e cfg.bigendian=true, same as .endian 1\n"
			".lil_endian     call e cfg.bigendian=false, same as .endian 0\n"
			".asciz \"msg\" zero byte terminated string\n"
			".string         non-null terminated string\n"
			".ascii          same as .string\n"
			".align          force a specific alignment when writing code\n"
			".arm            set asm.bits=32 when asm.arch=arm\n"
			".thumb          set asm.bits=16 when asm.arch=arm\n"
			".arch [mips]    specify asm.arch\n"
			".bits [32|64]   specify 8,16,32,64 e asm.bits\n"
			".fill [count]   fill N bytes with zeroes\n"
			".kernel [ios]   set asm.os=linux,windows,macos,...\n"
			".cpu [name]     set asm.cpu=?\n"
			".os [os]        same as .kernel\n"
			".hex 102030     set bytes in linear hexpair string, no endian applied\n"
			".int16 [num]    write int16 number honoring endian\n"
			".int32 [num]    same for 32bit\n"
			".int64 [num]    same for 64bit\n"
			".size           n/a\n"
			".section        n/a\n"
			".byte 0x10,0x20 space or comma separated list of byte values\n"
			".glob           n/a\n"
			".equ K=V        define K to be replaced with V in the lines below\n"
			".org            change the PC=$$ to make relative instructions work\n"
			".text           tell the linker where the code starts\n"
			".data           tell the linker where the data starts\n"
			".incbin foo.bin include binary file\n"
			);
	}
	return 0;
}

static int bin_len(const char *s) {
	int len = 0;
	while (*s) {
		if (*s == '_') {
			s++;
		} else {
			if (*s != '0' && *s != '1') {
				break;
			}
			len++;
			s++;
		}
	}
	return len? len: -1;
}

static int is_binary(const char *s) {
	if (r_str_startswith (s, "Bx")) {
		return bin_len (s + 2);
	}
	if (r_str_startswith (s, "0b") && (bin_len (s + 2) % 8) == 0) {
		return bin_len (s + 2);
	}
	int len = 0;
	while (*s) {
		if (*s == '_') {
			s++;
			continue;
		}
		if (*s != '0' && *s != '1') {
			if (*s == 'b' && !s[1] && (len % 8) == 0) {
				return len;
			}
			return 0;
		}
		s++;
		len++;
	}
	return 0;
}

static int rasm_disasm(RAsmState *as, ut64 addr, const char *buf, int len, int bits, int bin, int hex) {
	RAsmCode *acode;
	ut8 *data = NULL;
	int ret = 0;
	ut64 clen = 0;
	if (bits == 1) {
		len /= 8;
	}
	ut8 bbuf[8] = {0};
	int blen = is_binary (buf);
	if (blen > 0) {
		if (r_str_startswith (buf, "Bx")) {
			buf += 2;
		}
		char *nstr = r_str_newf ("%s%s", r_str_startswith (buf, "0b")? "": "0b", buf);
		if (nstr[strlen (nstr) - 1] == 'b') {
			nstr[strlen (nstr)-1] = 0;
		}
		ut64 n = r_num_get (NULL, nstr);
		free (nstr);
		memcpy (bbuf, &n, 8);
		buf = (const char*)&bbuf;
		bin = true;
		hex = false;
		if (blen > 32) {
			r_write_ble64 (&bbuf, n, !R_SYS_ENDIAN);
			len = 8;
		} else {
			r_write_ble32 (&bbuf, n, !R_SYS_ENDIAN);
			len = 4;
		}
	}
	if (bin) {
		if (len < 0) {
			return false;
		}
		clen = len; // XXX
		data = (ut8 *)buf;
	} else {
		clen = r_hex_str2bin (buf, NULL);
		if ((int)clen < 1 || !(data = malloc (clen))) {
			ret = 0;
			goto beach;
		}
		r_hex_str2bin (buf, data);
		len = clen;
	}

	if (!len || clen <= len) {
		len = clen;
	}

	if (hex == 2) {
		RAnalOp aop = {0};
		while (ret < len) {
			aop.size = 0;
			if (r_anal_op (as->anal, &aop, addr, data + ret, len - ret, R_ARCH_OP_MASK_ESIL) > 0) {
				printf ("%s\n", R_STRBUF_SAFEGET (&aop.esil));
			}
			if (aop.size < 1) {
				R_LOG_ERROR ("Invalid");
				break;
			}
			ret += aop.size;
			r_anal_op_fini (&aop);
		}
	} else if (hex) {
		r_asm_set_pc (as->a, addr);
		while ((len - ret) > 0) {
			RAsmOp op;
			int dr = r_asm_disassemble (as->a, &op, data + ret, len - ret);
			if (dr == -1 || op.size < 1) {
				op.size = 1;
				r_asm_op_set_asm (&op, "invalid");
			}
			char *op_hex = r_asm_op_get_hex (&op);
			printf ("0x%08" PFMT64x "  %2d %24s  %s\n",
				as->a->pc, op.size, op_hex,
				r_asm_op_get_asm (&op));
			free (op_hex);
			ret += op.size;
			r_asm_set_pc (as->a, addr+ ret);
			r_asm_op_fini (&op);
		}
	} else {
		r_asm_set_pc (as->a, addr);
		if (!(acode = r_asm_mdisassemble (as->a, data, len))) {
			goto beach;
		}
		if (as->oneliner) {
			r_str_replace_char (acode->assembly, '\n', ';');
			printf ("%s\"\n", acode->assembly);
		} else {
			printf ("%s", acode->assembly);
		}
		ret = acode->len;
		r_asm_code_free (acode);
	}
beach:
	if (data && data != (ut8 *)buf) {
		free (data);
	}
	return ret;
}

static void print_buf(RAsmState *as, char *str) {
	int i;
	if (as->coutput) {
		printf ("\"");
		for (i = 1; *str; str += 2, i += 2) {
			if (!(i % 41)) {
				printf ("\" \\\n\"");
				i = 1;
			}
			printf ("\\x%c%c", *str, str[1]);
		}
		printf ("\"\n");
	} else {
		printf ("%s\n", str);
	}
}

static bool print_label(void *user, const void *k, const void *v) {
	printf ("f label.%s = %s\n", (const char *)k, (const char *)v);
	return true;
}

static int rasm_asm(RAsmState *as, const char *buf, ut64 offset, ut64 len, int bits, int bin, bool use_spp, bool hexwords) {
	RAsmCode *acode;
	int i, j, ret = 0;
	r_asm_set_pc (as->a, offset);
	if (!(acode = r_asm_rasm_assemble (as->a, buf, use_spp))) {
		return 0;
	}
	if (acode->len) {
		ret = acode->len;
		if (bin) {
			if ((ret = write (1, acode->bytes, acode->len)) != acode->len) {
				R_LOG_ERROR ("Failed to write buffer");
				r_asm_code_free (acode);
				return 0;
			}
		} else {
			int b = acode->len;
			if (bits == 1) {
				int bytes = (b / 8) + 1;
				for (i = 0; i < bytes; i++) {
					for (j = 0; j < 8 && b--; j++) {
						printf ("%c", (acode->bytes[i] & (1 << j))? '1': '0');
					}
				}
				printf ("\n");
			} else {
				if (hexwords) {
					size_t i = 0;
					for (i = 0; i < acode->len; i += sizeof (ut32)) {
						ut32 dword = r_read_ble32 (acode->bytes + i, R_SYS_ENDIAN);
						printf ("0x%08x ", dword);
						if ((i/4) == 7) {
							printf ("\n");
						}
					}
					printf ("\n");
				} else {
					char* str = r_asm_code_get_hex (acode);
					if (str) {
						print_buf (as, str);
						free (str);
					}
				}
			}
		}
	}
	r_asm_code_free (acode);
	return (ret > 0);
}

/* asm callback */
static int __lib_asm_cb(RLibPlugin *pl, void *user, void *data) {
	RAsmPlugin *hand = (RAsmPlugin *)data;
	RAsmState *as = (RAsmState *)user;
	r_asm_add (as->a, hand);
	return true;
}

/* anal callback */
static int __lib_anal_cb(RLibPlugin *pl, void *user, void *data) {
	RAnalPlugin *hand = (RAnalPlugin *)data;
	RAsmState *as = (RAsmState *)user;
	r_anal_add (as->anal, hand);
	return true;
}

static int print_assembly_output(RAsmState *as, const char *buf, ut64 offset, ut64 len, int bits, int bin, bool use_spp, bool rad, bool hexwords, const char *arch) {
	if (rad) {
		printf ("e asm.arch=%s\n", arch? arch: R_SYS_ARCH);
		printf ("e asm.bits=%d\n", bits? bits: R_SYS_BITS);
		if (offset) {
			printf ("s 0x%"PFMT64x"\n", offset);
		}
		printf ("wx ");
	}
	int ret = rasm_asm (as, (char *)buf, offset, len, as->a->config->bits, bin, use_spp, hexwords);
	if (rad) {
		printf ("f entry = $$\n");
		printf ("f label.main = $$ + 1\n");
		if (as->a->flags) {
			ht_pp_foreach (as->a->flags, print_label, NULL);
		}
	}
	return ret;
}

static void __load_plugins(RAsmState *as) {
	char *tmp = r_sys_getenv ("RASM2_NOPLUGINS");
	if (tmp) {
		free (tmp);
		return;
	}
	r_lib_add_handler (as->l, R_LIB_TYPE_ASM, "(dis)assembly plugins", &__lib_asm_cb, NULL, as);
	r_lib_add_handler (as->l, R_LIB_TYPE_ANAL, "analysis/emulation plugins", &__lib_anal_cb, NULL, as);

	char *path = r_sys_getenv (R_LIB_ENV);
	if (path && *path) {
		r_lib_opendir (as->l, path);
	}

	// load plugins from the home directory
	char *homeplugindir = r_xdg_datadir ("plugins");
	r_lib_opendir (as->l, homeplugindir);
	free (homeplugindir);

	// load plugins from the system directory
	char *plugindir = r_str_r2_prefix (R2_PLUGINS);
	char *extrasdir = r_str_r2_prefix (R2_EXTRAS);
	char *bindingsdir = r_str_r2_prefix (R2_BINDINGS);
	r_lib_opendir (as->l, plugindir);
	r_lib_opendir (as->l, extrasdir);
	r_lib_opendir (as->l, bindingsdir);
	free (plugindir);
	free (extrasdir);
	free (bindingsdir);

	free (tmp);
	free (path);
}

static char *io_slurp(const char *file, size_t *len) {
	RIODesc *des = NULL;
	ut8 *ret = NULL;
	RIO *io = r_io_new ();
	if (io) {
		des = r_io_open_nomap (io, file, R_PERM_R, 0);
		if (des) {
			ut64 size = r_io_desc_size (des);
			ret = (ut8*)malloc (size + 1);
			if (size >= ST32_MAX || !ret || !r_io_read (io, ret, size)) {
				R_FREE (ret);
			} else {
				*len = size;
				ret[size] = '\0';
			}
		}
	}
	r_io_desc_free (des);
	r_io_free (io);
	return (char *)ret;
}

R_API int r_main_rasm2(int argc, const char *argv[]) {
	const char *env_arch = r_sys_getenv ("RASM2_ARCH");
	const char *env_bits = r_sys_getenv ("RASM2_BITS");
	const char *arch = R_SYS_ARCH;
	const char *cpu = NULL;
	const char *kernel = NULL;
	const char *filters = NULL;
	const char *file = NULL;
	bool list_plugins = false;
	bool list_anal_plugins = false;
	bool list_arch_plugins = false;
	bool isbig = false;
	bool rad = false;
	bool use_spp = false;
	bool hexwords = false;
	ut64 offset = 0;
	int fd = -1, dis = 0, bin = 0, ret = 0, c, whatsop = 0;
	int bits = (R_SYS_BITS & R_SYS_BITS_64)? 64: 32;
	int help = 0;
	ut64 len = 0, idx = 0, skip = 0;
	bool analinfo = false;

	if (argc < 2) {
		return rasm_show_help (1);
	}

	char *log_level = r_sys_getenv ("R2_LOG_LEVEL");
	if (R_STR_ISNOTEMPTY (log_level)) {
		r_log_set_level (atoi (log_level));
	}
	R_FREE (log_level);
	RAsmState *as = __as_new ();

	// TODO set addrbytes
	char *r2arch = r_sys_getenv ("R2_ARCH");
	if (r2arch) {
		arch = r2arch;
	}

	char *r2bits = r_sys_getenv ("R2_BITS");
	if (r2bits) {
		bits = r_num_math (NULL, r2bits);
		free (r2bits);
	}

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "a:Ab:Bc:CdDeEf:F:hi:jk:l:L@:o:O:pqrs:vwx");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			arch = opt.arg;
			break;
		case 'A':
			analinfo = true;
			break;
		case 'b':
			bits = r_num_math (NULL, opt.arg);
			break;
		case 'B':
			bin = 1;
			break;
		case 'c':
			cpu = opt.arg;
			break;
		case 'C':
			as->coutput = true;
			break;
		case 'd':
			dis = 1;
			break;
		case 'D':
			dis = 2;
			break;
		case 'e':
			isbig = true;
			break;
		case 'E':
			dis = 3;
			break;
		case 'f':
			file = opt.arg;
			break;
		case 'F':
			filters = opt.arg;
			break;
		case 'h':
			help++;
		case 'i':
			skip = r_num_math (NULL, opt.arg);
			break;
		case 'j':
			as->json = true;
			break;
		case 'k':
			kernel = opt.arg;
			break;
		case 'l':
			len = r_num_math (NULL, opt.arg);
			break;
		case 'L':
			if (list_anal_plugins) {
				list_arch_plugins = true;
			} else if (list_plugins) {
				list_anal_plugins = true;
			} else {
				list_plugins = true;
			}
			break;
		case '@':
		case 'o':
			offset = r_num_math (NULL, opt.arg);
			break;
		case 'O':
			fd = open (opt.arg, O_TRUNC | O_RDWR | O_CREAT, 0644);
#ifndef __wasi__
			if (fd != -1) {
				dup2 (fd, 1);
			}
#endif
			break;
		case 'p':
			use_spp = true;
			break;
		case 'q':
			as->quiet = true;
			break;
		case 'r':
			rad = true;
			break;
		case 's':
			if (*opt.arg == '?') {
				printf ("att\nintel\nmasm\njz\nregnum\n");
				__as_free (as);
				return 0;
			} else {
				int syntax = r_asm_syntax_from_string (opt.arg);
				if (syntax == -1) {
					__as_free (as);
					return 1;
				}
				r_asm_set_syntax (as->a, syntax);
			}
			break;
		case 'v':
			if (as->quiet) {
				printf ("%s\n", R2_VERSION);
			} else {
				ret = r_main_version_print ("rasm2");
			}
			goto beach;
		case 'w':
			whatsop = true;
			break;
		case 'x':
			hexwords = true;
			break;
		default:
			ret = rasm_show_help (0);
			goto beach;
		}
	}

	if (help > 0) {
		ret = rasm_show_help (help > 1? 2: 0);
		goto beach;
	}
	if (list_arch_plugins) {
		rarch2_list (as, opt.argv[opt.ind]);
		ret = 1;
		goto beach;
	}
	if (list_anal_plugins) {
		ranal2_list (as, opt.argv[opt.ind]);
		ret = 1;
		goto beach;
	}
	if (list_plugins) {
		rasm2_list (as, opt.argv[opt.ind]);
		ret = 1;
		goto beach;
	}

	if (arch) {
		if (!r_asm_use (as->a, arch)) {
			R_LOG_ERROR ("Unknown asm plugin '%s'", arch);
			ret = 0;
			goto beach;
		}
		r_anal_use (as->anal, arch);
	} else if (env_arch) {
		if (!r_asm_use (as->a, env_arch)) {
			R_LOG_ERROR ("Unknown asm plugin '%s'", env_arch);
			ret = 0;
			goto beach;
		}
	} else if (!r_asm_use (as->a, R_SYS_ARCH)) {
		R_LOG_ERROR ("Cannot find " R_SYS_ARCH " plugin");
		ret = 0;
		goto beach;
	}
	if (cpu) {
		r_asm_set_cpu (as->a, cpu);
	}
	r_asm_set_bits (as->a, (env_bits && *env_bits)? atoi (env_bits): bits);
	r_anal_set_bits (as->anal, (env_bits && *env_bits)? atoi (env_bits): bits);
	as->a->syscall = r_syscall_new ();
	r_syscall_setup (as->a->syscall, arch, bits, cpu, kernel);
	{
		bool canbebig = r_asm_set_big_endian (as->a, isbig);
		if (isbig && !canbebig) {
			R_LOG_WARN ("This architecture can't swap to big endian");
		}
	}
	if (whatsop) {
		const char *s = r_asm_describe (as->a, opt.argv[opt.ind]);
		ret = 1;
		if (s) {
			printf ("%s\n", s);
			ret = 0;
		}
		goto beach;
	}
	if (filters) {
		char *p = strchr (filters, ':');
		if (p) {
			*p = 0;
			if (*filters) {
				r_asm_sub_names_input (as->a, filters);
			}
			if (p[1]) {
				r_asm_sub_names_output (as->a, p + 1);
			}
			*p = ':';
		} else {
			if (dis) {
				r_asm_sub_names_output (as->a, filters);
			} else {
				r_asm_sub_names_input (as->a, filters);
			}
		}
	}

	if (file) {
		char *content;
		size_t length = 0;
		const int bits = as->a->config->bits;
		if (!strcmp (file, "-")) {
			int sz = 0;
			ut8 *buf = (ut8 *)r_stdin_slurp (&sz);
			if (!buf || sz < 1) {
				R_LOG_INFO ("Nothing to do");
				free (buf);
				goto beach;
			}
			len = (ut64)sz;
			if (dis) {
				if (skip && length > skip) {
					if (bin) {
						memmove (buf, buf + skip, length - skip);
						length -= skip;
					}
				}
				ret = rasm_disasm (as, offset, (char *)buf, len, bits, bin, dis - 1);
			} else if (analinfo) {
				ret = show_analinfo (as, (const char *)buf, offset);
			} else {
				ret = print_assembly_output (as, (char *)buf, offset, len,
					bits, bin, use_spp, rad, hexwords, arch);
			}
			ret = !ret;
			free (buf);
		} else {
			content = r_file_slurp (file, &length);
			if (!content) {
				content = (char *)io_slurp (file, &length);
			}
			if (content) {
				if (length > ST32_MAX) {
					R_LOG_ERROR ("File %s is too big", file);
					ret = 1;
				} else {
					if (len && len > 0 && len < length) {
						length = len;
					}
					content[length] = '\0';
					if (skip && length > skip) {
						if (bin) {
							memmove (content, content + skip, length - skip);
							length -= skip;
						}
					}
					if (dis) {
						ret = rasm_disasm (as, offset, content,
								length, bits, bin, dis - 1);
					} else if (analinfo) {
						ret = show_analinfo (as, (const char *)content, offset);
					} else {
						ret = print_assembly_output (as, content, offset, length,
								bits, bin, use_spp, rad, hexwords, arch);
					}
					ret = !ret;
				}
				free (content);
			} else {
				R_LOG_ERROR ("Cannot open file %s", file);
				ret = 1;
			}
		}
	} else if (opt.argv[opt.ind]) {
		if (!strcmp (opt.argv[opt.ind], "-")) {
			int length;
			do {
				char buf[1024]; // TODO: use(implement) r_stdin_line() or so
				length = read (0, buf, sizeof (buf) - 1);
				if (length < 1) {
					break;
				}
				if (len > 0 && len < length) {
					length = len;
				}
				buf[length] = 0;
				if ((!bin || !dis) && feof (stdin)) {
					break;
				}
				if (skip && length > skip) {
					if (bin) {
						memmove (buf, buf + skip, length - skip + 1);
						length -= skip;
					}
				}
				if (!bin || !dis) {
					int buflen = strlen ((const char *)buf);
					if (buf[buflen] == '\n') {
						buf[buflen - 1] = '\0';
					}
				}
				if (dis) {
					ret = rasm_disasm (as, offset, (char *)buf, length, bits, bin, dis - 1);
				} else if (analinfo) {
					ret = show_analinfo (as, (const char *)buf, offset);
				} else {
					ret = rasm_asm (as, (const char *)buf, offset, length, bits, bin, use_spp, hexwords);
				}
				idx += ret;
				offset += ret;
				if (!ret) {
					goto beach;
				}
			} while (!len || idx < length);
			ret = idx;
			goto beach;
		}
		if (dis) {
			char *usrstr = strdup (opt.argv[opt.ind]);
			len = strlen (usrstr);
			if (skip && len > skip) {
				skip *= 2;
				memmove (usrstr, usrstr + skip, len - skip);
				len -= skip;
				usrstr[len] = 0;
			}
			if (r_str_startswith (usrstr, "0x")) {
				memmove (usrstr, usrstr + 2, strlen (usrstr + 2) + 1);
			}
			if (rad) {
				as->oneliner = true;
				printf ("e asm.arch=%s\n", arch? arch: R_SYS_ARCH);
				printf ("e asm.bits=%d\n", bits);
				printf ("\"wa ");
			}
			ret = rasm_disasm (as, offset, (char *)usrstr, len,
					as->a->config->bits, bin, dis - 1);
			free (usrstr);
		} else if (analinfo) {
			ret = show_analinfo (as, (const char *)opt.argv[opt.ind], offset);
		} else {
			ret = print_assembly_output (as, opt.argv[opt.ind], offset, len, as->a->config->bits,
							bin, use_spp, rad, hexwords, arch);
		}
		if (!ret) {
			R_LOG_DEBUG ("assembly failed");
		}
		ret = !ret;
	}
beach:
	__as_free (as);

	free (r2arch);
	if (fd != -1) {
		close (fd);
	}
	return ret;
}
