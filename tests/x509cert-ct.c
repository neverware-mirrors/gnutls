/*
 * Copyright (C) 2020 Free Software Foundation, Inc.
 *
 * Author: Ander Juaristi
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Parts copied from other tests */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils.h"

static char pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIG+jCCBeKgAwIBAgIQPurql+NcbKQ/8rR9djN5DDANBgkqhkiG9w0BAQsFADCB\n"
"hDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8w\n"
"HQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTUwMwYDVQQDEyxTeW1hbnRl\n"
"YyBDbGFzcyAzIFNlY3VyZSBTZXJ2ZXIgU0hBMjU2IFNTTCBDQTAeFw0xNzAzMjAw\n"
"MDAwMDBaFw0yMDAzMjQyMzU5NTlaMHMxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhO\n"
"ZXcgWW9yazERMA8GA1UEBwwITmV3IFlvcmsxJzAlBgNVBAoMHkFtZXJpY2FuIENp\n"
"dmlsIExpYmVydGllcyBVbmlvbjEVMBMGA1UEAwwMd3d3LmFjbHUub3JnMIIBIjAN\n"
"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAui9XzdLmI2JH+05y4WAV7jHn2Vyk\n"
"k+92pm/mdQcfJDyNR6gotaLBvBy9n9SeDj03eGlYUKZ1lgBeHhM17FMWuWoazETl\n"
"EU2Iq1ugHn3V+Rr2IkQ8f00RcNXRlYCQOiL0WYrrXPHZUNh1aQ4kwFaFGT0iNsKS\n"
"kGwf56b1goJujqwtLIBzRdHOLzWGCq1Kn/VeDTi2QQyTVQLWsDZzZApUXMyoc1xv\n"
"go7r1lvHWbJ04up0YwXssC67lw4SKK+/2lZF0Fu0baooHQOlQ5jk0DQhQ6Hsgp/t\n"
"UYhrv56cVf9MWrBEbVBg79yiyWb+rrXhk9KeMbFFsxNEWiA5TREejEhVXwIDAQAB\n"
"o4IDdjCCA3IwMgYDVR0RBCswKYIPYWN0aW9uLmFjbHUub3Jnggx3d3cuYWNsdS5v\n"
"cmeCCGFjbHUub3JnMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgWgMGEGA1UdIARa\n"
"MFgwVgYGZ4EMAQICMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20v\n"
"Y3BzMCUGCCsGAQUFBwICMBkMF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMCsGA1Ud\n"
"HwQkMCIwIKAeoByGGmh0dHA6Ly9zZy5zeW1jYi5jb20vc2cuY3JsMB0GA1UdJQQW\n"
"MBQGCCsGAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBTbYiD7fQKJfNI7b8fk\n"
"MmwFUh2tsTBXBggrBgEFBQcBAQRLMEkwHwYIKwYBBQUHMAGGE2h0dHA6Ly9zZy5z\n"
"eW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6Ly9zZy5zeW1jYi5jb20vc2cuY3J0\n"
"MIIB9gYKKwYBBAHWeQIEAgSCAeYEggHiAeAAdQDd6x0reg1PpiCLga2BaHB+Lo6d\n"
"AdVciI09EcTNtuy+zAAAAVrspLZKAAAEAwBGMEQCIEuVHq0xyXfN8XP0Ly8eTEJB\n"
"3XMAKhaercn0EqjtgNUPAiBN+/pUJ9EwF4yh2hRU1U3KkdzTI+KDerLZCl004ADF\n"
"cgB3AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAABWuyktugAAAQD\n"
"AEgwRgIhAPoMU/iz0Ne4vgM4cQol7zLVS8xEc18natc9EgLpOqvvAiEAtyt6nMg7\n"
"18/axecg1fk2dcDKCP8EpEJWnabnDRwMb00AdgDuS723dc5guuFCaR+r4Z5mow9+\n"
"X7By2IMAxHuJeqj9ywAAAVrspLadAAAEAwBHMEUCIH8pZN5die2lOt6i2NS57xxd\n"
"uo12mGZ4Xt6cPARVZCipAiEAxOGXK63gCml0jZnlBAN/41YMCNF0cCl9rMIRmEOe\n"
"ffYAdgC8eOHfxfY8aEZJM02hD6FfCXlpIAnAgbTz9pF/Ptm4pQAAAVrspLdAAAAE\n"
"AwBHMEUCIDtHn+q93n/mGGzdFZb9PImevE3t8yi4FpEKQh3fN+HdAiEA618tN/lR\n"
"9m8dh0BVfHAJ9o3CAT53sWjO37sFhHPNOT4wDQYJKoZIhvcNAQELBQADggEBALEV\n"
"pKCM+njCWn74ThjbBEH23rWDYNU3Dl4O5J1U0wJdp4uTvZQbTHlvuAYnQr2WUBX5\n"
"OOvZdVLKDZJqZ/KJ2TLjBUQGWHylu6kE2PWuOTrJ6eC2UnR8zj0RavELHXuGUmQt\n"
"p5UESDjGI6IUDfI6IdxIKydnIStQLuKlaGsz3bsD1yc8XfCNjkmxf3DfC2qnnO6q\n"
"0i2o1SkjCesCqrgPQuVM95vF5I+dRcrk1nHOLCgDLYeoOSFpkPzk5EF7gDrfuLHn\n"
"a7MqZSlOcbf6XcGmsOPH0SCYLyNiJwuBX2W3fw2rP9adpWniGK5kyIEU6Nrkgc31\n"
"ESMyYNL3A9igh1jySzg=\n"
"-----END CERTIFICATE-----\n";

static int check_scts(const gnutls_datum_t *ext)
{
	/* TODO implement */
	return 1;
}

#define MAX_DATA_SIZE 1024

void doit(void)
{
	int ret, scts_printed = 0;
	size_t oidlen;
	char oid[MAX_DATA_SIZE];
	gnutls_x509_crt_t cert;
	gnutls_datum_t ext, xpem = { (void *) pem, sizeof(pem) - 1 };

	global_init();
	if (debug)
		gnutls_global_set_log_level(5);

	gnutls_x509_crt_init(&cert);
	ret = gnutls_x509_crt_import(cert, &xpem, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("gnutls_x509_crt_import");

	for (unsigned i = 0; ; i++) {
		oidlen = MAX_DATA_SIZE;

		ret = gnutls_x509_crt_get_extension_oid(cert, i, oid, &oidlen);
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		if (ret < 0)
			fail("gnutls_x509_crt_get_extension_oid");

		if (strcmp(oid, GNUTLS_X509EXT_OID_CT_SCT) == 0) {
			ret = gnutls_x509_crt_get_extension_data2(cert, i, &ext);
			if (ret < 0)
				fail("gnutls_x509_crt_get_extension_data2");
			if (!check_scts(&ext))
				break;
			scts_printed = 1;
			break;
		}
	}

	gnutls_x509_crt_deinit(cert);

	if (!scts_printed)
		fail("SCT extension not found\n");

	gnutls_global_deinit();
	if (debug)
		success("success");
}
