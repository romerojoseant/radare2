/* radare - LGPL3 - 2021 - Jose_Ant_Romero */

#include <r_bin.h>
#include <magic/ascmagic.c>

typedef struct s390_hdr_cesd {
	ut8 Identification;	// 0x20
	ut8 Flag;
	ut16 Reserved;
	ut16 ESDID;
	ut16 Count;
} S390_Header_CESD;

typedef struct s390_hdr_cesd_data {
	ut8 Symbol[8];
	ut8 Type;
	ut8 Address[3];
	ut8 Zeros;
	ut8 ID_or_Length[3];
} S390_Header_CESD_DATA;

typedef struct s390_hdr_csect {
	ut8 Identification;	// 0x80
	ut8 Count;
	ut8 SubType;
} S390_Header_CSECT;

typedef struct s390_hdr_contrec {
	ut8 Identificacion; // 0x01, 0x05 & 0x0d
	ut8 Zeros1[3];
	ut16 Count;
	ut16 Zeros2;
	ut8	CCW[8];
} S390_Header_ControlRecord;

typedef struct s390_hdr_contrec_data {
	ut16 EntryNumber;
	ut16 Length;
} S390_Header_ControlRecord_Data;

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static bool check_buffer(RBinFile *bf, RBuffer *b) {
	ut8 buf[8] = {0};
	r_buf_read_at (b, 0, buf, sizeof (buf));
	if (buf[0] == 0x20) {
		S390_Header_CESD *hdr = (S390_Header_CESD*)buf; 
		if (r_buf_size (b) > sizeof (S390_Header_CESD) + r_read_be16(&hdr->Count)) {
			return true;
		}
	}
	return false; 
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb){
	return check_buffer (bf, b);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->machine = strdup ("s390");
	ret->bclass = strdup("XX");
	ret->type = strdup ("load module");
	ret->os = strdup ("s390");
	ret->arch = strdup ("s390");
	ret->bits = 32;
	ret->has_va = 0;
	ret->big_endian = 1;
	return ret;
}

/* static void addsym(RList *ret, const char *name, ut64 addr) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = strdup (r_str_get (name));
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = 0;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
} */

/* static void showstr(const char *str, const ut8 *s, size_t len) {
	char *msg = r_str_ndup ((const char *) s, len);
	eprintf ("%s: %s\n", str, msg);
	free (msg);
} */

static RList *symbols(RBinFile *bf) {
	RList *ret = NULL;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

/*	ut8 gbuf[16] = {0};
	int left = r_buf_read_at (bf->buf, 0, gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		return NULL;
	}
	if(!memcmp (gbuf, "AB", 2)) {
		S390_Header_ROM *hdr = (S390_Header_ROM*)gbuf;
		addsym (ret, "ROMSignature", r_offsetof (S390_Header_ROM, ROMSignature));
		addsym (ret, "InitAddress", r_read_le16 (&hdr->InitAddress));
		addsym (ret, "RuntimeAddress", r_read_le16 (&hdr->RuntimeAddress));
		addsym (ret, "DeviceAddress", r_read_le16 (&hdr->DeviceAddress));
		addsym (ret, "PointAddress", r_read_le16 (&hdr->PointAddress));

		eprintf ("InitAddress: 0x%04x\n", (ut16) hdr->InitAddress);
		eprintf ("RuntimeAddress: 0x%04x\n", (ut16) hdr->RuntimeAddress);
		eprintf ("DeviceAddress: 0x%04x\n", (ut16) hdr->DeviceAddress);
		eprintf ("PointAddress: 0x%04x\n", (ut16) hdr->PointAddress);
	} else if (gbuf[0] == 0xFE) {
		S390_Header_BIN *hdr = (S390_Header_BIN*)gbuf;
		addsym (ret, "BINSignature", r_read_be8 (&hdr->BINSignature));
		addsym (ret, "StartAddress", r_read_be16 (&hdr->StartAddress));
		addsym (ret, "EndAddress", r_read_be16 (&hdr->EndAddress));
		addsym (ret, "InitAddress", r_read_be16 (&hdr->InitAddress));

		eprintf ("StartAddress: 0x%04x\n", (ut16) hdr->StartAddress);
		eprintf ("EndAddress: 0x%04x\n", (ut16) hdr->EndAddress);
		eprintf ("InitAddress: 0x%04x\n", (ut16) hdr->InitAddress);
	}
*/
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}

	S390_Header_CESD hdr20 = {0};
	S390_Header_CESD_DATA hdrd = {0};
	S390_Header_CSECT hdr80 = {0};
	S390_Header_ControlRecord hdr01 = {0};
	S390_Header_ControlRecord_Data hdrcd = {0};

	ut16 lon;
	int left;
	ut16 x = 0;
	bool endw = false;

	ut8 gbuf[1] = {0};
	left = r_buf_read_at (bf->buf, 0, gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		return NULL;
	}

	while (!endw) {
		switch (gbuf[0]) {
			case 0x20:
				left = r_buf_read_at (bf->buf, x, (ut8*)&hdr20, sizeof (S390_Header_CESD));
				if (left < sizeof (S390_Header_CESD)) {
					return NULL;
				}

				lon = r_read_be16(&hdr20.Count);
				eprintf("Register 0x%02x - Count: 0x%04x - 0x%04x - %04ld\n", 
								gbuf[0], x, lon, lon / sizeof(S390_Header_CESD_DATA));
				x += sizeof(S390_Header_CESD);

				for (ut16 y = 0 ; y < lon / sizeof(S390_Header_CESD_DATA) ; y++) {
					left = r_buf_read_at (bf->buf, x, (ut8*)&hdrd, sizeof (S390_Header_CESD_DATA));
					if (left < sizeof (S390_Header_CESD_DATA)) {
						return NULL;
					}

					ut8 cad[8];
					from_ebcdic(hdrd.Symbol, sizeof(hdrd.Symbol), cad);
					ut32 a;
					ut32 b;
					a = (hdrd.Address[0] * 65536) + (hdrd.Address[1] * 256) + (hdrd.Address[2]);
					b = (hdrd.ID_or_Length[0] * 65536) + (hdrd.ID_or_Length[1] * 256) + (hdrd.ID_or_Length[2]);
					eprintf ("    - Symbol: %s - 0x%04x - 0x%04x\n", r_str_ndup ((char *) cad, 8), a, b); 

					x += sizeof(S390_Header_CESD_DATA);
				}

				left = r_buf_read_at (bf->buf, x, gbuf, sizeof (gbuf));
				if (left < sizeof (gbuf)) {
					return NULL;
				}
				break;
			
			case 0x80:
				left = r_buf_read_at (bf->buf, x, (ut8*)&hdr80, sizeof(S390_Header_CSECT));
				if (left < sizeof (S390_Header_CSECT)) {
					return NULL;
				}
				eprintf("Register 0x%02x - Count: 0x%04x - 0x%02x\n", gbuf[0], x, hdr80.Count);
				x += sizeof(S390_Header_CSECT);

				// To Do something with IDR data
				x += hdr80.Count - 2;

//				Last IDR data has as SubType 1--- ----
//				if (hdr80.SubType & 0x080) {
//					eprintf("End of CSECT\n");
//					endw = true;
//				}

				left = r_buf_read_at (bf->buf, x, gbuf, sizeof (gbuf));
				if (left < sizeof (gbuf)) {
					return NULL;
				}
				break;
			
			case 0x01:
			case 0x05:
			case 0x0d:
				left = r_buf_read_at (bf->buf, x, (ut8*)&hdr01, sizeof(S390_Header_ControlRecord));
				if (left < sizeof (S390_Header_ControlRecord)) {
					return NULL;
				}
				lon = r_read_be16(&hdr01.Count);
				eprintf("Register 0x%02x - Count: 0x%04x - 0x%04x - %04ld\n", 
								gbuf[0], x, lon, lon / sizeof(S390_Header_ControlRecord_Data));
				x += sizeof(S390_Header_ControlRecord);

				for (ut16 y = 0 ; y < lon / sizeof(S390_Header_ControlRecord_Data) ; y++) {
					left = r_buf_read_at (bf->buf, x, (ut8*)&hdrcd, sizeof (S390_Header_ControlRecord_Data));
					if (left < sizeof (S390_Header_ControlRecord_Data)) {
						return NULL;
					}

					eprintf ("    - ContRec: 0x%04x - 0x%04x\n", 
								r_read_be16(&hdrcd.EntryNumber), r_read_be16(&hdrcd.Length)); 
					x += sizeof(S390_Header_ControlRecord_Data);
				}

				left = r_buf_read_at (bf->buf, x, gbuf, sizeof (gbuf));
				if (left < sizeof (gbuf)) {
					return NULL;
				}
				eprintf("End - Count: 0x%02x - 0x%04x\n", x, gbuf[0]);
				endw = true;
				break;
		}
	}

/*	RBinSection *ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("header");
	ptr->paddr = ptr->vaddr = 0;
	ut64 baddr = 0;
	ut64 hdrsize = 0;
	if (!memcmp (gbuf, "AB", 2)) {
		S390_Header_ROM *hdr = (S390_Header_ROM*)gbuf;
		baddr = r_read_le16 (&hdr->InitAddress) & 0xff00;
		hdrsize = ptr->vsize = sizeof (hdr);
	} else if (gbuf[0] == 0xFE) {
		S390_Header_BIN *hdr = (S390_Header_BIN*)gbuf;
		baddr = r_read_le16 (&hdr->StartAddress) & 0xff00;
		hdrsize = ptr->vsize = sizeof (hdr);
	}

	ptr->size = hdrsize;
	ptr->perm = R_PERM_R;
	ptr->add = true;
	r_list_append (ret, ptr);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("text");
	ptr->paddr = 0;
	ptr->vaddr = baddr;
	ptr->size = ptr->vsize = r_buf_size (bf->buf) - hdrsize;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);
*/
	return ret;
}

static RList *entries(RBinFile *bf) { 
	RList *ret = r_list_new ();
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	if (!ret || !ptr) {
		free (ret);
		free (ptr);
		return NULL;
	}
/*	ut8 gbuf[32];
	int left = r_buf_read_at (bf->buf, 0, (ut8*)&gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		free (ret);
		free (ptr);
		return NULL;
	}
	if (!memcmp (gbuf, "AB", 2)) {
		S390_Header_ROM *hdr = (S390_Header_ROM*)gbuf;
		ut16 init = r_read_le16 (&hdr->InitAddress);
		ptr->vaddr = init;
		ptr->paddr = 0;
		r_list_append (ret, ptr);
	} else if (gbuf[0] == 0xFE) {
		S390_Header_BIN *hdr = (S390_Header_BIN*)gbuf;
		ut16 init = r_read_le16 (&hdr->InitAddress);
		ptr->vaddr = init;
		ptr->paddr = 0;
		r_list_append (ret, ptr);
	}
*/
	return ret;
}

RBinPlugin r_bin_plugin_s390 = {
	.name = "s390",
	.desc = "s390 Load Module parser",
	.license = "LGPL3",
	.author = "Jose Antonio Romero",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.minstrlen = 3
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_s390,
	.version = R2_VERSION
};
#endif
