// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "imitate_shim.h"
#include "imitate.h"

static enum imitate_proto proto_of(const char *s)
{
	if (!strcmp(s, "quic")) return IMITATE_QUIC;
	if (!strcmp(s, "dns"))  return IMITATE_DNS;
	if (!strcmp(s, "stun")) return IMITATE_STUN;
	if (!strcmp(s, "sip"))  return IMITATE_SIP;
	return IMITATE_NONE;
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int unhex(const char *s, u8 *out, int max)
{
	int n = (int)strlen(s) / 2, i;

	if (n > max) return -1;
	for (i = 0; i < n; i++)
		out[i] = (u8)((hexval(s[2 * i]) << 4) | hexval(s[2 * i + 1]));
	return n;
}

/* Prefix row:  <proto> <pad> <payload_hex> <output_hex>      (4 fields)
 * Whole row:   <proto> whole <len> <seed_hex> <output_hex>   (5 fields) */
int main(int argc, char **argv)
{
	FILE *f;
	char line[8192];
	int pass = 0, fail = 0;

	if (argc < 2) { fprintf(stderr, "usage: harness <vectors.txt>\n"); return 2; }
	f = fopen(argv[1], "r");
	if (!f) { perror("fopen"); return 2; }

	while (fgets(line, sizeof(line), f)) {
		char proto[16], f2[16], lenstr[16], seedhex[16], outhex[8192], payhex[4096];
		u8 want[8192], got[8192], payload[4096], seedbuf[4];
		enum imitate_proto p;

		if (sscanf(line, "%15s %15s %15s %15s %8191s",
			   proto, f2, lenstr, seedhex, outhex) == 5 &&
		    !strcmp(f2, "whole")) {
			int len = atoi(lenstr);
			int wn = unhex(outhex, want, sizeof(want));
			u32 seed;

			if (unhex(seedhex, seedbuf, 4) != 4)
				continue;
			seed = ((u32)seedbuf[0] << 24) | ((u32)seedbuf[1] << 16) |
			       ((u32)seedbuf[2] << 8) | (u32)seedbuf[3];
			memset(got, 0, len);
			imitate_fill_whole(got, len, seed, p = proto_of(proto));
			if (wn == len && !memcmp(got, want, len)) pass++;
			else { fail++; fprintf(stderr, "FAIL %s whole len=%d\n", proto, len); }
			continue;
		}
		/* Prefix row: re-parse the 4-field layout. */
		if (sscanf(line, "%15s %15s %4095s %8191s",
			   proto, lenstr, payhex, outhex) == 4) {
			int pad = atoi(lenstr);
			int pn = unhex(payhex, payload, sizeof(payload));
			int wn = unhex(outhex, want, sizeof(want));
			int total = pad + pn;

			memset(got, 0, total);
			memcpy(got + pad, payload, pn);
			imitate_fill_prefix(got, total, pad, p = proto_of(proto));
			if (wn == total && !memcmp(got, want, total)) pass++;
			else { fail++; fprintf(stderr, "FAIL %s pad=%d\n", proto, pad); }
		}
	}
	fclose(f);
	fprintf(stderr, "pass=%d fail=%d\n", pass, fail);
	return fail ? 1 : 0;
}
