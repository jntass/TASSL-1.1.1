/*
 * Written by caichenghang for the TaSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 - 2018 Beijing JN TASS Technology Co.,Ltd.  All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Beijing JN TASS
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * 4. The name "TaSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    TaSSL@tass.com.cn.
 *
 * 5. Products derived from this software may not be called "TaSSL"
 *    nor may "TaSSL" appear in their names without prior written
 *    permission of the TaSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Beijing JN TASS
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE TASSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE TASSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software developed by the TaSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/sm2.h"

/*TEST KAP*/
int main(int argc, char *argv[])
{
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
	int asn1_flag = OPENSSL_EC_NAMED_CURVE;
	EC_GROUP *group = NULL;
	EC_KEY *A_key = NULL, *B_key = NULL, *A_ecdhe_key = NULL, *B_ecdhe_key = NULL;
	int loop, retval;
	unsigned char Buffer[256];
	size_t keylen = 48;
    char *tmp = NULL;

	OpenSSL_add_all_algorithms();

	/*首先设定SM2曲线*/
	/*Tested for NONE SM2DH_TEST*/
	group = EC_GROUP_new_by_curve_name(NID_sm2/*OBJ_sn2nid("SM2")*/);
	if (group == NULL)
	{
		printf("Error Of Create curve to SM2\n");
		goto err;
	}

	A_key = EC_KEY_new();
	B_key = EC_KEY_new();
	A_ecdhe_key = EC_KEY_new();
	B_ecdhe_key = EC_KEY_new();

	if (!A_key || !B_key || !A_ecdhe_key || !B_ecdhe_key)
		goto err;

	if (!EC_KEY_set_group(A_key, group) || !EC_KEY_set_group(B_key, group) || !EC_KEY_set_group(A_ecdhe_key, group) || !EC_KEY_set_group(B_ecdhe_key, group))
		goto err;

    if (EC_KEY_generate_key(A_key) == 0)
        goto err;

	if (EC_KEY_generate_key(B_key) == 0)
        goto err;
    
    if (EC_KEY_generate_key(A_ecdhe_key) == 0)
        goto err;

	if (EC_KEY_generate_key(B_ecdhe_key) == 0)
        goto err;
	
    {
		printf("----------------Test Calculate By Side A:------------------\n");
		memset(Buffer, 0, sizeof(Buffer));
        
        tmp = EC_POINT_point2hex(group, EC_KEY_get0_public_key(A_key), POINT_CONVERSION_UNCOMPRESSED, NULL);
		printf("Pa : [%s]\n", tmp);
        OPENSSL_free(tmp); tmp = NULL;

        tmp = EC_POINT_point2hex(group, EC_KEY_get0_public_key(A_ecdhe_key), POINT_CONVERSION_UNCOMPRESSED, NULL);
		printf("Ra : [%s]\n", tmp);
        OPENSSL_free(tmp); tmp = NULL;

		memset(Buffer, 0, sizeof(Buffer));

		/*retval = SM2Kap_compute_key(Buffer, 46, 0, "BILL456@YAHOO.COM", 17, "ALICE123@YAHOO.COM", 18, B_ecdhe_key, A_ecdhe_key, B_key, A_key, EVP_sm3());*/
		retval = SM2Kap_compute_key(Buffer, keylen, 0, 
                SM2_DEFAULT_USERID, strlen(SM2_DEFAULT_USERID), SM2_DEFAULT_USERID, strlen(SM2_DEFAULT_USERID), 
                B_ecdhe_key, A_ecdhe_key, B_key, A_key, EVP_sm3());
		if (retval <= 0)
		{
			printf("Compute ECDHE Key Error\n");
			goto err;
		}

		printf("SM2 Shared Key: [");
		for (loop = 0; loop < retval; loop++)
			printf("%02X", Buffer[loop] & 0xff);
		printf("]\n");
	}
	

    {
		printf("----------------Test Calculate By Side B:------------------\n");
		memset(Buffer, 0, sizeof(Buffer));
		
        tmp = EC_POINT_point2hex(group, EC_KEY_get0_public_key(B_key), POINT_CONVERSION_UNCOMPRESSED, NULL);
        printf("Pb : [%s]\n", tmp);
        OPENSSL_free(tmp); tmp = NULL;

        tmp = EC_POINT_point2hex(group, EC_KEY_get0_public_key(B_ecdhe_key), POINT_CONVERSION_UNCOMPRESSED, NULL);
		printf("Rb : [%s]\n", tmp);
        OPENSSL_free(tmp); tmp = NULL;

		memset(Buffer, 0, sizeof(Buffer));

    	/*retval = SM2Kap_compute_key(Buffer, keylen, 1, "ALICE123@YAHOO.COM", 18, "BILL456@YAHOO.COM", 17, A_ecdhe_key, B_ecdhe_key, A_key, B_key, EVP_sm3());*/
		retval = SM2Kap_compute_key(Buffer, keylen, 1, 
                SM2_DEFAULT_USERID, strlen(SM2_DEFAULT_USERID), SM2_DEFAULT_USERID, strlen(SM2_DEFAULT_USERID), 
                A_ecdhe_key, B_ecdhe_key, A_key, B_key, EVP_sm3());
		if (retval <= 0)
		{
			printf("Compute ECDHE Key Error\n");
			goto err;
		}

		printf("SM2 Shared Key: [");
		for (loop = 0; loop < retval; loop++)
			printf("%02X", Buffer[loop] & 0xff);
		printf("]\n");
	}

err:
    if (tmp) OPENSSL_free(tmp);
	if (A_key) EC_KEY_free(A_key);
	if (B_key) EC_KEY_free(B_key);
	if (A_ecdhe_key) EC_KEY_free(A_ecdhe_key);
	if (B_ecdhe_key) EC_KEY_free(B_ecdhe_key);
	if (group) EC_GROUP_free(group);
	return 0;
}
