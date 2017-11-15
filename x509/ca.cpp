#define ILM_APPLIANCE

#include <cstdlib>

#include <sys/stat.h>
#include <sys/types.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#include "qmgmt.hpp"
#include "x509.hpp"
#include "ca.hpp"

void GeneratePassword(char *pass, int sz)
{
	unsigned int rnum;
	register int i;

	for (i = 0; i < sz; )
	{
		RAND_bytes((unsigned char *)&rnum, sizeof(rnum));
		rnum = rnum%90;
		if (rnum > 47)
		{
			if (isalnum(rnum))
				pass[i++] = rnum;
		}
	}
	pass[sz] = 0;
}

CCA::~CCA() 
{
	if (m_caCert)
		delete m_caCert;
}

CCA::CCA(std::string &serialFile)
{
    InitCrypto();

    m_serialNo = 1;
    m_caCert = new CX509Certificate;
	m_serialFile = serialFile;

	m_valid = access(m_serialFile.c_str(), F_OK ) != -1; 
}

bool CCA::GenerateCACert(std::vector <std::string> &args)
{
	if (m_valid)
		return false;

	std::string pass = "";

	return GenerateCACert(args, pass);
}

bool CCA::GenerateCACert(std::vector <std::string> &args, std::string &pswd)
{
	if (m_valid)
		return false;

	for (int i = 0; i < args.size(); i++)
		printf("%s\n", args[i].c_str());

	bool rv = false;

	m_certFile = args[SAVE_FILE];
	m_keyFile = args[SAVE_KEY_FILE];

	EVP_PKEY *pkey = EVP_PKEY_new();
	if (pkey)
	{
		X509 *x509 = X509_new();
		if (x509)
		{
			RSA *rsa = RSA_new();
			BIGNUM *bn = BN_new();
			BN_set_word(bn, RSA_F4);

			if (!RSA_generate_key_ex(rsa, atoi(args[KEY_STRENGTH].c_str()), bn, NULL))
			{
				char buf[8192];

				unsigned long e = ERR_get_error();
				printf("%lu %s\n", e, ERR_error_string(e, buf)); 
				exit(1);
			}
			BN_free(bn);
			bn = NULL;
            
			if (EVP_PKEY_assign_RSA(pkey, rsa))
			{
				X509_NAME *name;

				printf("Serial number %d\n", m_serialNo);
 				X509_set_version(x509, 2L);
				ASN1_INTEGER_set(X509_get_serialNumber(x509), (unsigned int )m_serialNo);
				X509_gmtime_adj(X509_get_notBefore(x509), 0);
				X509_gmtime_adj(X509_get_notAfter(x509), (long)60*60*24*atoi(args[EXPIRATION_DAYS].c_str()));
				X509_set_pubkey(x509, pkey);
                
				name = X509_NAME_new();

                X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const BYTE *)args[COMMON_NAME].c_str(), -1, -1, 0);
                X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const BYTE *)args[COMPANY_NAME].c_str(), -1, -1, 0);
                X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const BYTE *)args[COMPANY_NAME].c_str(), -1, -1, 0);
                X509_NAME_add_entry_by_txt(name,"C", MBSTRING_ASC, (const BYTE *)args[COUNTRY_NAME].c_str(), -1, -1, 0);
				X509_set_subject_name(x509, name);
				X509_set_issuer_name(x509, name);

				X509_NAME_free(name);

				// Self sign the cert
				if (X509_sign(x509, pkey, EVP_md5()))
				{
                    m_caCert->SetCertificate(x509);
                    m_caCert->SetKey(pkey);
                  
				  	rv = m_caCert->SaveCertificate(m_certFile, FORMAT_PEM) &&
						m_caCert->SavePrivateKey(m_keyFile, FORMAT_PEM, EVP_aes_256_cbc(), (uint8_t *)pswd.c_str(), pswd.length());
				
					pkey->pkey.rsa = NULL;
				}

				if (rv)
				{
					m_serialNo++;
					FILE *fp = fopen(m_serialFile.c_str(), "wb");
					fwrite(&m_serialNo, sizeof(m_serialNo), 1, fp);
					fclose(fp);
					m_valid = 1;
				}
			}

			rsa = NULL;
			X509_free(x509);
		}
		EVP_PKEY_free(pkey);
	}

	return rv;
}

bool CCA::LoadCACert(std::string &certFile, std::string &keyFile, std::string &pswd)
{
	if (!m_valid)
		return false;

	struct stat sts;

	if (m_caCert)
		delete m_caCert;

	m_caCert = NULL;
	m_certFile = certFile;
	m_keyFile = keyFile;

	bool rv = (stat(m_certFile.c_str(), &sts) == 0) && (stat(m_keyFile.c_str(), &sts) == 0);
	if (rv)
	{
		m_caCert = new CX509Certificate(m_certFile, FORMAT_PEM, m_keyFile, FORMAT_PEM, (uint8_t *)pswd.c_str());
		rv = m_caCert->CanSign() && m_caCert->CanVerify();
	}

	return rv;
}

CX509Certificate *CCA::Certificate()
{
	return m_caCert;
}

CX509Certificate *CCA::GenerateCertificate(CX509Request &req, int days)
{
	if (!m_valid)
		return NULL;

	CX509Certificate *x = NULL;

	FILE *fp = fopen(m_serialFile.c_str(), "rb");
	if (fp != NULL)
	{
		int serial;

		fread(&serial, sizeof(serial), 1, fp);
		fclose(fp);
		printf("Serial = %d\n", serial);
		x = new CX509Certificate(req, *m_caCert, days, serial);
		if (x)
		{
			serial++;
			fp = fopen(m_serialFile.c_str(), "wb");
			fwrite(&serial, sizeof(serial), 1, fp);
			fclose(fp);
		}
	}

	return x;
}

std::string CCA::GetCertFile() {return m_certFile;} 
std::string CCA::GetKeyFile() {return m_keyFile;}

bool CCA::IsValid(){return m_valid;}
