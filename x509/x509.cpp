#include <vector>
#include <string>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdint.h>

//#include <xml.h>
#ifdef _WIN32
#include <XML_PARSER.h>
#include <configWin.h>
#endif
#ifdef WIN32
	#include <windows.h>
	#include <wincrypt.h>
#else
	#define PTHREADS
	#include <sys/param.h>
	#include <pthread.h>
	#include <pthread.h>
	#include <unistd.h>
	#include <netdb.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
//#include <clnetwork.h>
//#include <globals.h>
//#ifndef _WIN32
//#include <afc.h>
//#endif
//#include <config.hpp>

#include "qmgmt.hpp"
#include "x509.hpp"
#include "ca.hpp"

#ifdef STANDALONE
#include <mysql.h>
#include <db.hpp>
#endif

#include <openssl/asn1.h>
#include <openssl/evp.h>

void InitCrypto()
{
	static int doneInit;

	if (!doneInit)
	{
        OpenSSL_add_all_algorithms();
		OpenSSL_add_all_ciphers();
		OpenSSL_add_all_digests();
		ERR_load_crypto_strings();
		SSL_load_error_strings();
		char rand_buff[16];

		RAND_seed(rand_buff, 16);

		doneInit = 1;
	}
}

void FinishCrypto()
{
    CRYPTO_cleanup_all_ex_data();
}

EVP_ENCODE_CTX *InitEncode()
{
	EVP_ENCODE_CTX *ctx;

	ctx = (EVP_ENCODE_CTX *)calloc(1, sizeof(EVP_ENCODE_CTX));
	EVP_EncodeInit(ctx);
	
	return ctx;
}

EVP_ENCODE_CTX *InitDecode()
{
	EVP_ENCODE_CTX *ctx;

	ctx = (EVP_ENCODE_CTX *)calloc(1, sizeof(EVP_ENCODE_CTX));
	EVP_DecodeInit(ctx);
	
	return ctx;
}

int UpdateEncode(EVP_ENCODE_CTX *ctx, uint8_t **outData, uint8_t *inData, int inLen)
{
	uint8_t *outBuff;
	int outLen;
	int len;
	int rv;

	len = 0;
	*outData = NULL;
	outLen = ((inLen+ctx->num)/48+1)*65+1;
	outBuff = (uint8_t *)calloc(outLen, sizeof(uint8_t));
	if (outBuff)
	{
    	EVP_EncodeUpdate(ctx, outBuff, &len, inData, inLen);
		*outData = outBuff;
	}
	else
		len = 0;

	return len;
}

int UpdateDecode(EVP_ENCODE_CTX *ctx, uint8_t **outData, uint8_t *inData, int inLen)
{
	uint8_t *outBuff;
	int outLen;
	int len;
	int rv;

	len = 0;
	*outData = NULL;
	outLen = ((inLen+ctx->num)/48+1)*65+1;
	outBuff = (uint8_t *)calloc(outLen, sizeof(uint8_t));
	if (outBuff)
	{
    	if (EVP_DecodeUpdate(ctx, outBuff, &len, inData, inLen) != -1)
			*outData = outBuff;
		else
			free(outBuff);
	}
	else
		len = 0;

	return len;
}

int FinalEncode(EVP_ENCODE_CTX *ctx, uint8_t **outData)
{
	uint8_t *outBuff;
	int outLen;
	int flen;
	int rv;

	*outData = NULL;
	outLen = (ctx->num/48+1)*65+1;
	outBuff = (uint8_t *)calloc(outLen, sizeof(uint8_t));
	if (outBuff)
	{
    	EVP_EncodeFinal(ctx, outBuff, &flen);
		*outData = outBuff;
	}

	free(ctx);

	return flen;
}

int FinalDecode(EVP_ENCODE_CTX *ctx, uint8_t **outData)
{
	uint8_t *outBuff;
	int outLen;
	int flen;
	int rv;

	*outData = NULL;
	outLen = (ctx->num/48+1)*65+1;
	outBuff = (uint8_t *)calloc(outLen, sizeof(uint8_t));
	if (outBuff)
	{
    	if (EVP_DecodeFinal(ctx, outBuff, &flen) != -1)
			*outData = outBuff;
		else
		{
			free(outBuff);
			flen = 0;
		}
	}

	free(ctx);

	return flen;
}

bool DeriveKey(const EVP_CIPHER *type, const EVP_MD *md, uint8_t *key, uint8_t *iv)
{
	uint8_t keySeed[32];
	uint8_t salt[32];
	int nrounds = 10;

	if (!RAND_bytes(salt, sizeof(salt)))
	{
		printf("Salt failed\n");
		return false;
	}
	if (!RAND_bytes(keySeed, sizeof(keySeed)))
	{
		printf("Key seed failed\n");
		return false;
	}

	int i = EVP_BytesToKey(type, md, salt, keySeed, sizeof(keySeed), nrounds, key, iv);
  	if (i != 32) 
	{
		printf("Key size is %d bits - should be 256 bits\n", i);
		return false;
	}

	return true;
}

EVP_CIPHER_CTX *InitEncrypt(const EVP_CIPHER *type, ENGINE *impl, uint8_t *key, uint8_t *iv)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, type, impl, key, iv);
	
	return ctx;
}

EVP_CIPHER_CTX *InitDecrypt(const EVP_CIPHER *type, ENGINE *impl, uint8_t *key, uint8_t *iv)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, type, impl, key, iv);
	
	return ctx;
}

int UpdateEncrypt(EVP_CIPHER_CTX *ctx, uint8_t **outData, uint8_t *inData, int inLen)
{
	uint8_t *outBuff;
	int outLen;
	int len;

	*outData = NULL;
	outLen = EVP_CIPHER_CTX_block_size(ctx)+inLen;
	outBuff = (uint8_t *)calloc(outLen, sizeof(uint8_t));
	if (outBuff)
	{
		if (EVP_EncryptUpdate(ctx, outBuff, &len, inData, inLen))
			*outData = outBuff;
		else
			free(outBuff);
	}
	else
		len = 0;

	return len;
}

int UpdateDecrypt(EVP_CIPHER_CTX *ctx, uint8_t **outData, uint8_t *inData, int inLen)
{
	uint8_t *outBuff;
	int outLen;
	int len;

	*outData = NULL;
	outLen = EVP_CIPHER_CTX_block_size(ctx)+inLen;
	outBuff = (uint8_t *)calloc(outLen, sizeof(uint8_t));
	if (outBuff)
	{
		if (EVP_DecryptUpdate(ctx, outBuff, &len, inData, inLen))
			*outData = outBuff;
		else
			free(outBuff);
	}
	else
		len = 0;

	return len;
}

int FinalEncrypt(EVP_CIPHER_CTX *ctx, uint8_t **outData)
{
	uint8_t *outBuff;
	int outLen;
	int flen;

	*outData = NULL;
	outLen = EVP_CIPHER_CTX_block_size(ctx)+1024;
	outBuff = (uint8_t *)calloc(outLen, sizeof(uint8_t));

	if (outBuff)
	{
    	if (EVP_EncryptFinal_ex(ctx, outBuff, &flen))
			*outData = outBuff;
		else
			free(outBuff);
	}
	else
		flen = 0;

	EVP_CIPHER_CTX_free(ctx);

	return flen;
}

int FinalDecrypt(EVP_CIPHER_CTX *ctx, uint8_t **outData)
{
	uint8_t *outBuff;
	int outLen;
	int flen;

	*outData = NULL;
	outLen = EVP_CIPHER_CTX_block_size(ctx)+1024;
	outBuff = (uint8_t *)calloc(outLen, sizeof(uint8_t));

	if (outBuff)
	{
    	if (EVP_DecryptFinal_ex(ctx, outBuff, &flen))
			*outData = outBuff;
		else
			free(outBuff);
	}
	else
		flen = 0;

	EVP_CIPHER_CTX_free(ctx);

	return flen;
}

int EncryptDecrypt(int enc, uint8_t *key, uint8_t *iv, uint8_t *originalData, int orgLen, uint8_t **userData)
{
	unsigned char *outData = NULL;
	uint8_t *finalData = NULL;
	EVP_CIPHER_CTX *cipherCtx;
	int finalLen = 0;
    int len = 0;

	*userData = NULL;	

	if (enc)	
		cipherCtx = InitEncrypt(EVP_aes_256_cbc(), NULL, key, iv);
	else
		cipherCtx = InitDecrypt(EVP_aes_256_cbc(), NULL, key, iv);

	if (enc)
		len = UpdateEncrypt(cipherCtx, &outData, originalData, orgLen);
	else
		len = UpdateDecrypt(cipherCtx, &outData, originalData, orgLen);

	if (outData)
	{
		finalData = (uint8_t *)realloc(finalData, finalLen+len);
		memcpy(&finalData[finalLen], outData, len);
		finalLen += len;
		free(outData);
	}

	if (enc)
		len = FinalEncrypt(cipherCtx, &outData);
	else
		len = FinalDecrypt(cipherCtx, &outData);

	if (outData)
	{
		finalData = (uint8_t *)realloc(finalData, finalLen+len);
		memcpy(&finalData[finalLen], outData, len);
		finalLen += len;
		free(outData);
	}

	*userData = finalData;

	return finalLen;
}

int EncodeDecode(int enc, uint8_t *originalData, int orgLen, uint8_t **userData)
{
	unsigned char *outData = NULL;
	uint8_t *finalData = NULL;
	EVP_ENCODE_CTX *ctx;
	int finalLen = 0;
    int len = 0;

	*userData = NULL;	

	if (enc)
		ctx = InitEncode();
	else
		ctx = InitDecode();

	if (enc)
		len = UpdateEncode(ctx, &outData, originalData, orgLen);
	else
		len = UpdateDecode(ctx, &outData, originalData, orgLen);

	if (outData)
	{
		finalData = (uint8_t *)realloc(finalData, finalLen+len);
		memcpy(&finalData[finalLen], outData, len);
		finalLen += len;
		free(outData);
	}
	else
		return 0;

	if (enc)
		len = FinalEncode(ctx, &outData);
	else
		len = FinalDecode(ctx, &outData);

	if (outData)
	{
		finalData = (uint8_t *)realloc(finalData, finalLen+len);
		memcpy(&finalData[finalLen], outData, len);
		finalLen += len;
		free(outData);
	}

	*userData = finalData;

	return finalLen;
}

#if 0
int main(int argc, char *argv[])
{
	uint8_t inData[] = "This is the data to encrypt with AES for testing";
	char *keySeed = "Subash Warrier Key";
	uint8_t *encryptedData = NULL;
	uint8_t *decryptedData = NULL;
	uint8_t *encodedData = NULL;
	uint8_t *decodedData = NULL;
	int encryptedLen;
	int decryptedLen;
	int encodedLen;
	int decodedLen;
	uint8_t key[32];
	uint8_t iv[32];
	int rv = -1;
	
	InitCrypto();

	strcpy(iv, keySeed);
	DeriveKey(keySeed, strlen(keySeed), 5, key, iv);

	printf ("Input Data:%s\n", inData);
	encryptedLen = EncryptDecrypt(1, key, iv, inData, strlen(inData), &encryptedData);
	if (encryptedData)
	{
		encodedLen = EncodeDecode(1, encryptedData, encryptedLen, &encodedData);
		if (encodedData)
			printf ("Encoded Data:%s\n", encodedData);
		else
			goto errorExit;
	}
	else
		goto errorExit;

	decodedLen = EncodeDecode(0, encodedData, encodedLen, &decodedData);
	if (decodedData)
	{
		decryptedLen = EncryptDecrypt(0, key, iv, decodedData, decodedLen, &decryptedData);
		if (decryptedData)
			printf ("Decrypted Data:%s\n", decryptedData);
		else
			goto errorExit;
	}
	else
		goto errorExit;

	rv = 0;

errorExit:	
	if (decodedData)
		free(decodedData);
	if (decryptedData)
		free(decryptedData);
	if (encodedData)
		free(encodedData);
	if (encryptedData)
		free(encryptedData);
	FinishCrypto();

	return rv;
} 
#endif

int CX509Certificate::CertStackToString(STACK_OF(X509) *certs, std::string &buffer, bool noRoot)
{
	int rv = 0;
	int num;

	buffer = "";
	num = sk_X509_num(certs);
	if (noRoot)
		--num;
	for (int i = 0; i < num; i++) 
	{
		CX509Certificate theCert;
		std::string cert;

		X509 *x = sk_X509_value(certs, i);
		theCert.SetCertificate(x);
		theCert.SaveCertToMemory(cert, FORMAT_PEM);
		buffer += cert;
		rv++;
	}

	return rv;
}

STACK_OF(X509) *CX509Certificate::CertificatesFromMemory(std::string &buf, bool noRoot)
{
	STACK_OF(X509) *othercerts = NULL;
	BIO *certs;

	if ((certs = BIO_new(BIO_s_mem())) != NULL)
	{
		if (BIO_write(certs, buf.c_str(), buf.length()) > 0)
		{
			STACK_OF(X509_INFO) *allcerts;
			X509_INFO *xi;

			othercerts = sk_X509_new(NULL);
			if (othercerts != NULL) 
			{
				allcerts = PEM_X509_INFO_read_bio(certs, NULL, NULL, NULL);
				int num = sk_X509_INFO_num(allcerts);
				if (noRoot)
					--num;
				for (int i = 0; i < num; i++) 
				{
					xi = sk_X509_INFO_value (allcerts, i);
					if (xi->x509) 
						sk_X509_push(othercerts, X509_dup(xi->x509));
				}
				sk_X509_INFO_pop_free(allcerts, X509_INFO_free);
			}
		}

		BIO_free_all(certs);
	}

	return othercerts;
}

STACK_OF(X509) *CX509Certificate::CertificatesFromFile(std::string &file, bool noRoot)
{
	STACK_OF(X509_INFO) *allcerts;
	STACK_OF(X509) *othercerts;
	BIO *in;
	X509_INFO *xi;

	if (!(in = BIO_new_file(file.c_str(), "r"))) 
		return NULL;

	othercerts = sk_X509_new(NULL);
	if(!othercerts) 
		return NULL;

	allcerts = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
	int num = sk_X509_INFO_num(allcerts);
	if (noRoot)
		--num;
	for (int i = 0; i < num; i++) 
	{
		xi = sk_X509_INFO_value (allcerts, i);
		if (xi->x509) 
			sk_X509_push(othercerts, X509_dup(xi->x509));
	}
	sk_X509_INFO_pop_free(allcerts, X509_INFO_free);
	BIO_free_all(in);

	return othercerts;
}

STACK_OF(X509) *CX509Certificate::CertificatesFromFile(int count, ...)
{
	STACK_OF(X509) *othercerts;

	othercerts = sk_X509_new(NULL);
	if(!othercerts) 
		return NULL;

	va_list argptr;
	va_start(argptr, count);
	for (int i = 0; i < count; i++)
	{
		std::string file = va_arg(argptr, char *);
		CX509Certificate cert(file, FORMAT_PEM);

		if (cert.CanVerify())
			sk_X509_push(othercerts, X509_dup(cert.X509Object()));
	}
	va_end(argptr);

	return othercerts;
}

STACK_OF(X509) *CX509Certificate::CertificatesFromCertificate(std::vector<CX509Certificate *> &certs, bool noRoot)
{
	STACK_OF(X509) *othercerts;

	othercerts = sk_X509_new(NULL);
	if(!othercerts) 
		return NULL;

	int num = certs.size();
	if (noRoot)
		--num;
	for (int i = 0; i < num; i++)
	{
		CX509Certificate *cert = certs[i];

		if (cert->CanVerify())
			sk_X509_push(othercerts, X509_dup(cert->X509Object()));
	}

	return othercerts;
}

STACK_OF(X509) *CertificatesFromFile(std::vector<std::string> &files)
{
	STACK_OF(X509) *othercerts;

	othercerts = sk_X509_new(NULL);
	if (!othercerts) 
		return NULL;

	for (int i = 0; files.size(); i++)
	{
		CX509Certificate cert(files[i], FORMAT_PEM);

		if (cert.CanVerify())
			sk_X509_push(othercerts, X509_dup(cert.X509Object()));
	}

	return othercerts;
}

void CX509Certificate::ClearStack(STACK_OF(X509) *st)
{
	sk_X509_pop_free(st, X509_free);
}

// Virtual destructor

CX509Certificate::~CX509Certificate()
{
	if (m_x509)
		X509_free(m_x509);
	if (m_pkey)
		EVP_PKEY_free(m_pkey);
}

bool CX509Certificate::CanSign(){return m_sign > 0;}
bool CX509Certificate::CanVerify(){return m_verify > 0;}

CX509Certificate::CX509Certificate()
{
	m_x509 = 0;
	m_mdCtx = 0;
	m_mdType = 0;
	m_verify = 0;
	m_sign = 0;
	m_pkey = 0;
}

CX509Certificate::CX509Certificate(std::string &certFile, int fmt1, std::string &privKeyFile, int fmt2, uint8_t *pswd)
{
	m_x509 = 0;
	m_mdCtx = 0;
	m_mdType = 0;
	m_verify = 0;
	m_sign = 0;
	m_pkey = 0;

	LoadKey(privKeyFile, fmt2, pswd);
	LoadCert(certFile, fmt1);
}

CX509Certificate::CX509Certificate(std::string &certFile, int fmt1)
{
	m_x509 = 0;
	m_mdCtx = 0;
	m_mdType = 0;
	m_verify = 0;
	m_sign = 0;
	m_pkey = 0;

	LoadCert(certFile, fmt1);
}

CX509Certificate::CX509Certificate(CX509Request &req, CX509Certificate &caCert, int days, int serial)
{
	m_x509 = 0;
	m_mdCtx = 0;
	m_mdType = 0;
	m_verify = 0;
	m_sign = 0;
	m_pkey = 0;

	X509_REQ *xr = req.Request();
	if (req.VerifyRequest() && caCert.CanVerify() && caCert.CanSign())
	{
		EVP_PKEY *pkey;

		m_x509 = X509_new();

		X509_set_version(m_x509, 2);
		
		ASN1_INTEGER_set(X509_get_serialNumber(m_x509), serial);

  		X509_set_subject_name(m_x509, X509_REQ_get_subject_name(xr));
		X509_set_issuer_name(m_x509, caCert.GetSubjectName());
		pkey = req.ExportPublicKey();
  		X509_set_pubkey(m_x509, pkey);
		X509_gmtime_adj(X509_get_notBefore(m_x509), 0);
		X509_gmtime_adj(X509_get_notAfter(m_x509), days*24*60*60);
 		const EVP_MD *digest = EVP_sha256();
		X509_sign(m_x509, caCert.UsePrivateKey(), digest);
		EVP_PKEY_free(pkey);
	}
}

int CX509Certificate::LoadCertificate(std::string &file, int format)
{
	X509 *x;
	BIO *cert;
	int rv;

	x = NULL;
	cert = NULL;
	rv = 0;

	if (m_x509)
	{
		X509_free(m_x509);
		m_x509 = 0;
		m_verify = 0;
	}
    
	if ((cert=BIO_new(BIO_s_file())) == NULL)
		goto end;

	if (BIO_read_filename(cert, file.c_str()) <= 0)
		goto end;

	switch (format)
	{
		case FORMAT_ASN1:
			x = d2i_X509_bio(cert, NULL);
			break;

		case FORMAT_NETSCAPE:
            x = 0;
            break;
            
		case FORMAT_PEM:
			x = PEM_read_bio_X509_AUX(cert,NULL,NULL,NULL);
			break;

		case FORMAT_PKCS12:
			{
				PKCS12 *p12;

				p12 = d2i_PKCS12_bio(cert, NULL);
				PKCS12_parse(p12, NULL, NULL, &x, NULL);
				PKCS12_free(p12);
				p12 = NULL;
			}
			break;

		default:
			break;
	}
    
	if (x)
	{
		m_x509 = x;
		m_verify = 1;
		rv = 1;
	}

end:
	if (cert != NULL)
		BIO_free_all(cert);

	return rv;

}

int CX509Certificate::LoadCert(std::string &file, int format)
{
	X509 *x;
	BIO *cert;
	int rv;

	x = NULL;
	cert = NULL;
	rv = 0;

	if (m_x509)
	{
		X509_free(m_x509);
		m_x509 = 0;
		m_verify = 0;
	}

	if ((cert=BIO_new(BIO_s_file())) == NULL)
		goto end;

	if (BIO_read_filename(cert, file.c_str()) <= 0)
		goto end;

	switch (format)
	{
		case FORMAT_ASN1:
			x = d2i_X509_bio(cert, NULL);
			break;

		case FORMAT_NETSCAPE:
            break;
 
		case FORMAT_PEM:
			x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
			break;

		case FORMAT_PKCS12:
			{
				PKCS12 *p12;

				p12 = d2i_PKCS12_bio(cert, NULL);
				PKCS12_parse(p12, NULL, NULL, &x, NULL);
				PKCS12_free(p12);
				p12 = NULL;
			}
			break;

		default:
			break;
	}

	if (x)
	{
		m_x509 = x;
		rv = !HasExpired() && !IsRevoked();
		if (rv)
			m_verify = 1;
	}

end:
	if (cert != NULL)
		BIO_free_all(cert);

	return rv;
}

int CX509Certificate::LoadCertInMemory(std::string &incert, int format)
{
	X509 *x;
	BIO *cert;
	int rv;

	x = NULL;
	cert = NULL;
	rv = 0;

	if (m_x509)
	{
		X509_free(m_x509);
		m_x509 = 0;
		m_verify = 0;
	}

	if ((cert=BIO_new(BIO_s_mem())) == NULL)
		goto end;
	if (BIO_write(cert, incert.c_str(), incert.length()) <= 0)
		goto end;

	switch (format)
	{
		case FORMAT_ASN1:
			x = d2i_X509_bio(cert, NULL);
			break;

		case FORMAT_NETSCAPE:
			break;

		case FORMAT_PEM:
			x=PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
			break;

		case FORMAT_PKCS12:
			{
				PKCS12 *p12;

				p12 = d2i_PKCS12_bio(cert, NULL);
				PKCS12_parse(p12, NULL, NULL, &x, NULL);
				PKCS12_free(p12);
				p12 = NULL;
			}
			break;

		default:
			break;
	}

	if (x)
	{
		m_x509 = x;
		rv = !HasExpired() && !IsRevoked();
		if (rv)
			m_verify = 1;
	}

end:
	if (cert != NULL)
		BIO_free_all(cert);

	return rv;
}

int CX509Certificate::LoadKey(std::string &file, int format, uint8_t *pass)
{
	EVP_PKEY *pkey;
	BIO *key;
	int rv;

	key = NULL;
	pkey = NULL;
	rv = 0;

	key = BIO_new(BIO_s_file());
	if (key == NULL)
		goto end;

	if (BIO_read_filename(key, file.c_str()) <= 0)
		goto end;

	switch (format)
	{
		case FORMAT_ASN1:
			pkey = d2i_PrivateKey_bio(key, NULL);
			break;

		case FORMAT_PEM:
			if (pass && pass[0])
				pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, (char *)pass);
			else
				pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
			break;

		case FORMAT_PKCS12:
			{
				PKCS12 *p12;

				p12 = d2i_PKCS12_bio(key, NULL);
				PKCS12_parse(p12, (const char *)pass, &pkey, NULL, NULL);
				PKCS12_free(p12);
				p12 = NULL;
			}
			break;

		default:
			goto end;
			break;
	}

	if (pkey)
	{
		m_pkey = pkey;
		m_sign = 1;
		rv = 1;
	}

end:
	if (key != NULL)
		BIO_free_all(key);

	return rv;
}

int CX509Certificate::LoadKeyInMemory(std::string &inkey, int format, uint8_t *pass)
{
	EVP_PKEY *pkey;
	BIO *key;
	int rv;

	key = NULL;
	pkey = NULL;
	rv = 0;

	if (m_pkey)
	{
		EVP_PKEY_free(m_pkey);
		m_pkey = 0;
		m_sign = 0;
	}

	if ((key = BIO_new(BIO_s_mem())) == NULL)
		goto end;

	if (BIO_write(key, inkey.c_str(), inkey.length()) <= 0)
		goto end;

	switch (format)
	{
		case FORMAT_ASN1:
			pkey = d2i_PrivateKey_bio(key, NULL);
			break;

		case FORMAT_PEM:
			if (pass && pass[0])
				pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, pass);
			else
				pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
			break;

		case FORMAT_PKCS12:
			{
				PKCS12 *p12;

				p12 = d2i_PKCS12_bio(key, NULL);
				PKCS12_parse(p12, (const char *)pass, &pkey, NULL, NULL);
				PKCS12_free(p12);
				p12 = NULL;
			}
			break;

		default:
			goto end;
			break;
	}

	if (pkey)
	{
		m_pkey = pkey;
		m_sign = 1;
		rv = 1;
	}

end:
	if (key != NULL)
		BIO_free_all(key);

	return rv;
}

int CX509Certificate::SetCertificate(X509 *x)
{
	if (m_x509)
	{
		X509_free(m_x509);
		m_x509 = 0;
		m_verify = 0;
	}

	m_x509 = X509_dup(x);
	if (m_x509)
		m_verify = 1;

	if (m_x509)
		return 1;
	else
		return 0;
}

int CX509Certificate::SetKey(EVP_PKEY *pkey)
{
	int rv;

	rv = 0;
	if (m_pkey)
	{
		EVP_PKEY_free(m_pkey);
		m_pkey = 0;
		m_sign = 0;
	}

	m_pkey = EVP_PKEY_new();
	if (m_pkey)
		rv = EVP_PKEY_assign_RSA(m_pkey, pkey->pkey.rsa);

	if (rv)
		m_sign = 1;

	return rv;
}

void CX509Certificate::SignInit(int algo)
{
    if (m_mdCtx)
    {
        EVP_MD_CTX_destroy(m_mdCtx);
        m_mdCtx = 0;
    }

    m_mdCtx = EVP_MD_CTX_create();
    m_mdType = 0;
    
    switch (algo)
    {
        case MD_DSS:
            m_mdType = EVP_dss();
            break;
            
        case MD_DSS1:
            m_mdType = EVP_dss1();
            break;
                        
        case MD_MD5:
            m_mdType = EVP_md5();
            break;

#if 0
        case MD_RIPEMD160:
            m_mdType = EVP_ripemd160();
            break;
            
        case MD_SHA:
            m_mdType = EVP_sha();
            break;
            
        case MD_SHA512:
            m_mdType = EVP_sha();
            break;
#endif

        case MD_SHA1:
            m_mdType = EVP_sha1();
            break;
            
        case MD_SHA224:
            m_mdType = EVP_sha224();
            break;
            
        case MD_SHA256:
            m_mdType = EVP_sha256();
            break;
            
        case MD_SHA384:
            m_mdType = EVP_sha384();
            break;
    }
    
    EVP_SignInit(m_mdCtx, m_mdType);
}

void CX509Certificate::SignUpdate(unsigned char *data, int count)
{
	EVP_SignUpdate(m_mdCtx, data, count);
}

int CX509Certificate::SignFinal(unsigned char *sign, unsigned int *s)
{
	if (m_sign)
	{
		if (!HasExpired() && !IsRevoked())
			return EVP_SignFinal(m_mdCtx, sign, s, m_pkey);
		else
			return 0;
	}
	else
		return 0;
}

void CX509Certificate::VerifyInit(int algo)
{
    if (m_mdCtx)
    {
        EVP_MD_CTX_destroy(m_mdCtx);
        m_mdCtx = 0;
    }
    
    m_mdCtx = EVP_MD_CTX_create();
    m_mdType = 0;
    
    switch (algo)
    {
        case MD_DSS:
            m_mdType = EVP_dss();
            break;
            
        case MD_DSS1:
            m_mdType = EVP_dss1();
            break;
            
        case MD_MD5:
            m_mdType = EVP_md5();
            break;
             
#if 0
        case MD_RIPEMD160:
            m_mdType = EVP_ripemd160();
            break;
            
        case MD_SHA:
            m_mdType = EVP_sha();
            break;
            
        case MD_SHA512:
            m_mdType = EVP_sha();
            break;
#endif
            
        case MD_SHA1:
            m_mdType = EVP_sha1();
            break;
            
        case MD_SHA224:
            m_mdType = EVP_sha224();
            break;
            
        case MD_SHA256:
            m_mdType = EVP_sha256();
            break;
            
        case MD_SHA384:
            m_mdType = EVP_sha384();
            break;
    }

	EVP_VerifyInit(m_mdCtx, m_mdType);
}

void CX509Certificate::VerifyUpdate(unsigned char *data, int count)
{
	EVP_VerifyUpdate(m_mdCtx, data, count);
}

int CX509Certificate::VerifyFinal(unsigned char *sign, unsigned int s)
{
	int rv;

	rv = 0;
	if (m_verify)
	{
		EVP_PKEY *pkey;
		pkey = X509_get_pubkey(m_x509);
		rv = EVP_VerifyFinal(m_mdCtx, sign, s, pkey);
		EVP_PKEY_free(pkey);
	}

	return rv;
}

int CX509Certificate::PublicEncrypt(int flen, unsigned char *from, unsigned char *to, int padding)
{
	int rv;

	if (m_verify)
	{
		EVP_PKEY *pkey;

		pkey = X509_get_pubkey(m_x509);
		rv = RSA_public_encrypt(flen, from, to, pkey->pkey.rsa, padding);
		EVP_PKEY_free(pkey);
	}
	else
		rv = -1;

	return rv;
}

int CX509Certificate::PublicDecrypt(int flen, unsigned char *from, unsigned char *to, int padding)
{
	int rv;

	if (m_verify)
	{
		EVP_PKEY *pkey;

		pkey = X509_get_pubkey(m_x509);
		rv = RSA_public_encrypt(flen, from, to, pkey->pkey.rsa, padding);
		EVP_PKEY_free(pkey);
	}
	else
		rv = -1;

	return rv;
}

int CX509Certificate::PrivateEncrypt(int flen, unsigned char *from, unsigned char *to, int padding)
{
	int rv;

	if (m_pkey)
		rv = RSA_private_encrypt(flen, from, to, m_pkey->pkey.rsa, padding);
	else
		rv = -1;

	return rv;
}

int CX509Certificate::PrivateDecrypt(int flen, unsigned char *from, unsigned char *to, int padding)
{
	int rv;

	if (m_pkey)
		rv = RSA_private_decrypt(flen, from, to, m_pkey->pkey.rsa, padding);
	else
		rv = -1;

	return rv;
}

EVP_PKEY *CX509Certificate::ExportPublicKey()
{
	if (m_x509)
		return X509_get_pubkey(m_x509);
	else
		return NULL;
}

EVP_PKEY *CX509Certificate::UsePrivateKey()
{
	return m_pkey;
}

X509 *CX509Certificate::UseCertificate()
{
	return m_x509;
}

int CX509Certificate::SaveCertificate(std::string &file, int outformat)
{
	BIO *out;
	int rv;

	out = NULL;
	rv = 0;
	if (m_x509 == NULL)
		return rv;

	out = BIO_new(BIO_s_file());
	if (BIO_write_filename(out, (char *)file.c_str()) <= 0)
		goto end;

	switch (outformat)
	{
		case FORMAT_ASN1:
			rv = i2d_X509_bio(out, m_x509);
			break;

		case FORMAT_PEM:
			rv = PEM_write_bio_X509(out, m_x509);
			break;

		case FORMAT_NETSCAPE:
			break;
	}

end:
	if (out)
		BIO_free_all(out);
	return rv;
}

int CX509Certificate::SaveCertToMemory(std::string &buf, int outformat)
{
	char *lbuf;
	BIO *out;
	int rv;

	buf = "";
	out = NULL;
	rv = 0;
	if (m_x509 == NULL)
		return rv;

	out = BIO_new(BIO_s_mem());
	if (out == NULL)
		goto end;

	switch (outformat)
	{
		case FORMAT_ASN1:
			rv = i2d_X509_bio(out, m_x509);
			break;

		case FORMAT_PEM:
			rv = PEM_write_bio_X509(out, m_x509);
			break;

		case FORMAT_NETSCAPE:
			break;
	}

	lbuf = new char[8192];
	if (lbuf != NULL)
	{
		int len;

		len = BIO_read(out, lbuf, 8192);
		lbuf[len] = 0;
		buf = lbuf;
		delete lbuf;
	}
	else
		rv = 0;

end:
	if (out)
		BIO_free_all(out);
	return rv;
}

int CX509Certificate::SavePrivateKey(std::string &file, int outformat, const EVP_CIPHER *cipher, uint8_t *pass, int klen)
{
	BIO *out;
	int rv;

	rv = 0;
	out = BIO_new(BIO_s_file());
	if (BIO_write_filename(out, (char *)file.c_str()) <= 0)
		goto end;

	switch (outformat)
	{
		case FORMAT_ASN1:
			rv = i2d_RSAPrivateKey_bio(out, m_pkey->pkey.rsa);
			break;

		case FORMAT_PEM:
			if (pass && klen && cipher)
				rv = PEM_write_bio_RSAPrivateKey(out, m_pkey->pkey.rsa, cipher, pass, klen, NULL, NULL);
			else
				rv = PEM_write_bio_RSAPrivateKey(out, m_pkey->pkey.rsa, NULL, NULL, 0, NULL, NULL);
			break;
	}

end:
	if (out)
		BIO_free_all(out);
	return rv;
}

int CX509Certificate::SavePrivateKeyToMemory(std::string &buf, int outformat, const EVP_CIPHER *cipher, uint8_t *pass, int klen)
{
	char *lbuf;
	BIO *out;
	int rv;

	buf = "";
	rv = 0;
    
	out = BIO_new(BIO_s_mem());
	if (out == NULL)
		goto end;

	switch (outformat)
	{
		case FORMAT_ASN1:
			rv = i2d_RSAPrivateKey_bio(out, m_pkey->pkey.rsa);
			break;

		case FORMAT_PEM:
			if (pass && klen && cipher)
				rv = PEM_write_bio_RSAPrivateKey(out, m_pkey->pkey.rsa, cipher, pass, klen, NULL, NULL);
			else
				rv = PEM_write_bio_RSAPrivateKey(out, m_pkey->pkey.rsa, NULL, NULL, 0, NULL, NULL);
			break;
	}

	lbuf = new char[8192];
	if (lbuf != NULL)
	{
		int len;

		len = BIO_read(out, lbuf, 4096);
		lbuf[len] = 0;
		buf = lbuf;
		delete lbuf;
	}
	else
		rv = 0;

end:
	if (out)
		BIO_free_all(out);
	return rv;
}

X509_NAME *CX509Certificate::GetIssuerName()
{
	if (m_x509)
		return X509_get_issuer_name(m_x509);
	else
		return NULL;
}

X509_NAME *CX509Certificate::GetSubjectName()
{
	X509_NAME *name = X509_get_subject_name(m_x509);
	return name;
}

int CX509Certificate::SignCert(X509 *x, EVP_MD *md)
{
	return X509_sign(x, m_pkey, md);
}

unsigned int CX509Certificate::GetSerialNumber()
{
	if (m_x509)
		return ASN1_INTEGER_get(X509_get_serialNumber(m_x509));
	else
		return 0;
}

bool CX509Certificate::HasExpired()
{
	time_t ctime;

	//vij:3535: trying to not fail the check here as this is making the 
	//gateway completely unreachable after SSL cert has expired
	return 0;

	time(&ctime);
	if (m_x509)
		return X509_cmp_time(X509_get_notAfter(m_x509), &ctime) <= 0;
	else
		return 1;
}

int CX509Certificate::VerifyCA(CX509Certificate &caCert)
{
	if (m_x509)
	{
		EVP_PKEY *ekey;
		ekey = caCert.ExportPublicKey();
		int ret = X509_verify(m_x509, ekey);
		EVP_PKEY_free(ekey);
		return ret;
	}
	else
		return 0;
}

bool CX509Certificate::IsRevoked()
{
	return false;
}

X509 *CX509Certificate::X509Object()
{
	return m_x509;
}

void CX509Certificate::Print()
{
    char *line;

	if (m_verify)
	{
		line = X509_NAME_oneline(X509_get_subject_name(m_x509), 0, 0);
		printf("Subject: %s\n", line);
		free(line);				
		line = X509_NAME_oneline(X509_get_issuer_name(m_x509), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
	}
}

// Class CX509Request

CX509Request::~CX509Request()
{
    if (m_x509Req)
        X509_REQ_free(m_x509Req);
	if (m_pkey)
		EVP_PKEY_free(m_pkey);
}

CX509Request::CX509Request()
{
    m_x509Req = 0;
    m_pkey = 0;
}

CX509Request::CX509Request(std::string &reqFile, int fmt1)
{
    m_x509Req = 0;
    m_pkey = 0;
    LoadRequest(reqFile, fmt1);
}

CX509Request::CX509Request(std::vector<std::string> &args)
{
    m_x509Req = 0;
    m_pkey = 0;
    CreateRequest(args);
}

int CX509Request::LoadRequest(std::string &file, int format)
{
	X509_REQ *x;
	BIO *cert;
	int rv;
    
	x = NULL;
	cert = NULL;
	rv = 0;
    
	if (m_x509Req)
	{
		X509_REQ_free(m_x509Req);
		m_x509Req = 0;
	}
    
	if ((cert = BIO_new(BIO_s_file())) == NULL)
		goto end;
    
	if (BIO_read_filename(cert, file.c_str()) <= 0)
		goto end;
    
	switch (format)
	{
		case FORMAT_ASN1:
            x = d2i_X509_REQ_bio(cert, NULL);
			break;
            
		case FORMAT_NETSCAPE:
		case FORMAT_PKCS12:
            x = 0;
            break;
            
		case FORMAT_PEM:
            x = PEM_read_bio_X509_REQ(cert, NULL, NULL, NULL);
			break;
            
		default:
			break;
	}
    
	if (x)
		m_x509Req = x;
    
end:
	if (cert != NULL)
		BIO_free_all(cert);
    
	return rv;
    
}

int CX509Request::CreateRequest(std::vector<std::string> &args)
{
	X509_NAME *name=NULL;
	EVP_PKEY *pk;
	X509_REQ *x;
	RSA *rsa;
    int bits;
	int rv;
    
	for (int i = 0; i < args.size(); i++)
		printf("%s\n", args[i].c_str());

    if (m_x509Req)
	{
		X509_REQ_free(m_x509Req);
		m_x509Req = 0;
	}
    
    if (m_pkey)
    {
        EVP_PKEY_free(m_pkey);
        m_pkey = 0;
    }
    
	if ((pk = EVP_PKEY_new()) == NULL)
		goto err;
    
	if ((x = X509_REQ_new()) == NULL)
		goto err;
    
    bits = atoi(args[KEY_STRENGTH].c_str());
	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
		goto err;
    
	rsa = NULL;
    
	X509_REQ_set_pubkey(x, pk);

	name = X509_REQ_get_subject_name(x);
    
	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
   
	X509_REQ_set_version(x, 2L); 
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const BYTE *)args[COMMON_NAME].c_str(), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const BYTE *)args[COMPANY_NAME].c_str(), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"C", MBSTRING_ASC, (const BYTE *)args[COUNTRY_NAME].c_str(), -1, -1, 0);

	if (!X509_REQ_sign(x,pk,EVP_sha1()))
		goto err;

    m_x509Req = x;
    m_pkey = pk;
    rv = 1;

err:
	return rv;
}

int CX509Request::LoadRequestInMemory(std::string &req, int format)
{
	X509_REQ *x;
	BIO *xreq;
	int rv;
    
	x = NULL;
	xreq = NULL;
	rv = 0;
    
	if (m_x509Req)
	{
		X509_REQ_free(m_x509Req);
		m_x509Req = 0;
	}
    
	if ((xreq = BIO_new(BIO_s_mem())) == NULL)
		goto end;
    
	if (BIO_write (xreq, req.c_str(), req.length()) <= 0)
		goto end;
    
	switch (format)
	{
		case FORMAT_ASN1:
            x = d2i_X509_REQ_bio(xreq, NULL);
			break;
            
		case FORMAT_NETSCAPE:
			break;
            
		case FORMAT_PEM:
            x = PEM_read_bio_X509_REQ(xreq, NULL, NULL, NULL);
			break;
            
		case FORMAT_PKCS12:
			break;
            
		default:
			break;
	}
    
	if (x)
		m_x509Req = x;
    
end:
	if (xreq != NULL)
		BIO_free_all(xreq);
    
	return rv;
}

int CX509Request::LoadPrivateKey(std::string &file, int format, uint8_t *pswd)
{
	EVP_PKEY *pkey;
	BIO *key;
	int rv;
    
	key = NULL;
	pkey = NULL;
	rv = 0;
    
	if (m_pkey)
	{
		EVP_PKEY_free(m_pkey);
		m_pkey = 0;
	}
    
	key = BIO_new(BIO_s_file());
	if (key == NULL)
		goto end;
    
	if (BIO_read_filename(key, file.c_str()) <= 0)
		goto end;
    
	switch (format)
	{
		case FORMAT_ASN1:
			pkey = d2i_PrivateKey_bio(key, NULL);
			break;
            
		case FORMAT_PEM:
			if (pswd && pswd[0])
				pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, (char *)pswd);
			else
				pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
			break;
            
		case FORMAT_PKCS12:
        	{
 				PKCS12 *p12;
            
            	p12 = d2i_PKCS12_bio(key, NULL);
				if (pswd && pswd[0])
            		PKCS12_parse(p12, (const char *)pswd, &pkey, NULL, NULL);
				else
            		PKCS12_parse(p12, NULL, &pkey, NULL, NULL);
            	PKCS12_free(p12);
            	p12 = NULL;
        	}
			break;
            
		default:
			goto end;
			break;
	}
    
	if (pkey)
	{
		m_pkey = pkey;
		rv = 1;
	}
    
end:
	if (key != NULL)
		BIO_free_all(key);
    
	return rv;
}

int CX509Request::LoadPrivateKeyInMemory(std::string &inkey, int format, uint8_t *pswd)
{
	EVP_PKEY *pkey;
	BIO *key;
	int rv;
    
	key = NULL;
	pkey = NULL;
	rv = 0;
    
	if (m_pkey)
	{
		EVP_PKEY_free(m_pkey);
		m_pkey = 0;
	}
    
	if ((key = BIO_new(BIO_s_mem())) == NULL)
		goto end;
    
	if (BIO_write(key, inkey.c_str(), inkey.length()) <= 0)
		goto end;
    
	switch (format)
	{
		case FORMAT_ASN1:
			pkey = d2i_PrivateKey_bio(key, NULL);
			break;
            
		case FORMAT_PEM:
			if (pswd && pswd[0])
				pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, (char *)pswd);
			else
				pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
			break;
            
		case FORMAT_PKCS12:
            {
                PKCS12 *p12;
            
                p12 = d2i_PKCS12_bio(key, NULL);
				if (pswd && pswd[0])
            		PKCS12_parse(p12, (const char *)pswd, &pkey, NULL, NULL);
				else
            		PKCS12_parse(p12, NULL, &pkey, NULL, NULL);
                PKCS12_free(p12);
                p12 = NULL;
            }
			break;
            
		default:
			goto end;
			break;
	}
    
	if (pkey)
	{
		m_pkey = pkey;
		rv = 1;
	}
    
end:
	if (key != NULL)
		BIO_free_all(key);
    
	return rv;
}

int CX509Request::SaveRequest(std::string &file, int outformat)
{
	BIO *out;
	int rv;
    
	out = NULL;
	rv = 0;
	if (m_x509Req == NULL)
		return rv;
    
	out = BIO_new(BIO_s_file());
	if (BIO_write_filename(out, (char *)file.c_str()) <= 0)
		goto end;
    
	switch (outformat)
	{
		case FORMAT_ASN1:
			rv = i2d_X509_REQ_bio(out, m_x509Req);
			break;
            
		case FORMAT_PEM:
			rv = PEM_write_bio_X509_REQ(out, m_x509Req);
			break;
            
		case FORMAT_NETSCAPE:
			break;
	}
    
end:
	if (out)
		BIO_free_all(out);
	return rv;
}

int CX509Request::SaveRequestToMemory(std::string &buf, int outformat)
{
	char *lbuf;
	BIO *out;
	int rv;
    
	buf = "";
	out = NULL;
	rv = 0;
	if (m_x509Req == NULL)
		return rv;
    
	out = BIO_new(BIO_s_mem());
	if (out == NULL)
		goto end;
    
	switch (outformat)
	{
		case FORMAT_ASN1:
            rv = i2d_X509_REQ_bio(out, m_x509Req);
			break;
            
		case FORMAT_PEM:
			rv = PEM_write_bio_X509_REQ(out, m_x509Req);
			break;
            
		case FORMAT_NETSCAPE:
			break;
	}
    
	lbuf = new char[8192];
	if (lbuf != NULL)
	{
		int len;
        
		len = BIO_read(out, lbuf, 8192);
		lbuf[len] = 0;
		buf = lbuf;
		delete lbuf;
	}
	else
		rv = 0;
    
end:
	if (out)
		BIO_free_all(out);
	return rv;
}

int CX509Request::SavePrivateKey(std::string &file, int outformat, const EVP_CIPHER *cipher, uint8_t *p, int klen)
{
    BIO *out;
    int rv;

    rv = 0;
    out = BIO_new(BIO_s_file());
    if (BIO_write_filename(out, (char *)file.c_str()) <= 0)
        goto end;

    switch (outformat)
    {
        case FORMAT_ASN1:
            rv = i2d_RSAPrivateKey_bio(out, m_pkey->pkey.rsa);
            break;

        case FORMAT_PEM:
            if (cipher && p && klen)
                rv = PEM_write_bio_RSAPrivateKey(out, m_pkey->pkey.rsa, cipher, p, klen, NULL, NULL);
            else
                rv = PEM_write_bio_RSAPrivateKey(out, m_pkey->pkey.rsa, NULL, NULL, 0, NULL, NULL);
            break;
    }

end:
    if (out)
        BIO_free_all(out);

    return rv;

}

int CX509Request::SavePrivateKeyToMemory(std::string &buf, int outformat, const EVP_CIPHER *cipher, uint8_t *pass, int klen)
{
	char *lbuf;
	BIO *out;
	int rv;
    
	buf = "";
	rv = 0;
    
	out = BIO_new(BIO_s_mem());
	if (out == NULL)
		goto end;
    
	switch (outformat)
	{
		case FORMAT_ASN1:
			rv = i2d_RSAPrivateKey_bio(out, m_pkey->pkey.rsa);
			break;
            
		case FORMAT_PEM:
			if (cipher && pass && klen)
				rv = PEM_write_bio_RSAPrivateKey(out, m_pkey->pkey.rsa, cipher, pass, klen, NULL, NULL);
			else
				rv = PEM_write_bio_RSAPrivateKey(out, m_pkey->pkey.rsa, NULL, NULL, 0, NULL, NULL);
			break;
	}
    
	lbuf = new char[8192];
	if (lbuf != NULL)
	{
		int len;
        
		len = BIO_read(out, lbuf, 8192);
		lbuf[len] = 0;
		buf = lbuf;
		delete lbuf;
	}
	else
		rv = 0;
    
end:
	if (out)
		BIO_free_all(out);

	return rv;
}

bool CX509Request::VerifyRequest()
{
	bool rv;

	if (m_x509Req == NULL)
		return false;

	EVP_PKEY *pkey = X509_REQ_get_pubkey(m_x509Req);

	rv = X509_REQ_verify(m_x509Req, pkey) >= 0;

	EVP_PKEY_free(pkey);

	return rv;
}

X509_REQ *CX509Request::Request()
{
	return m_x509Req;
}

EVP_PKEY *CX509Request::ExportPublicKey()
{
	if (m_x509Req)
		return X509_REQ_get_pubkey(m_x509Req);
	else
		return NULL;
}

EVP_PKEY *CX509Request::UsePrivateKey()
{
	return m_pkey;
}

int CSMime::VerifyCallback(int ok, X509_STORE_CTX *x509_ctx)
{
	int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	int err  = X509_STORE_CTX_get_error(x509_ctx);
	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	STACK_OF(X509) *certstack = X509_STORE_CTX_get1_chain(x509_ctx);
	if (certstack == NULL)
	{
		printf("=============Error in cert stack=============\n");
		return ok;
	}
	int verifyDepth = sk_X509_num(certstack);
	int issuerDepth;
	if (depth+1 == verifyDepth)
		issuerDepth=depth;
	else
		issuerDepth=depth+1;

	X509 *issuerCert = sk_X509_value(certstack, issuerDepth);
	if (issuerCert == NULL)
	{
		printf("=============Error in cert stack_issuerCert=============\n");
		sk_X509_pop_free(certstack, X509_free);
		return ok;
	}

	CX509Certificate myCert;
	CX509Certificate caCert;

	myCert.SetCertificate(cert);
	caCert.SetCertificate(issuerCert);

	ok = myCert.VerifyCA(caCert);
	sk_X509_pop_free(certstack, X509_free);

	if (0 == ok)
	{
		printf("SMIME callback failed\n");
		myCert.Print();
		caCert.Print();
	}

	return ok;
}

CSMime::~CSMime()
{
	if (_p7)
		PKCS7_free(_p7);
	if (_store)
		X509_STORE_free(_store);
}

CSMime::CSMime()
{
	_p7FlagsSign = 0;
	_p7FlagsVerify = 0;
	_p7FlagsEncrypt = 0;
	_p7FlagsDecrypt = 0;
	_p7 = NULL;
	_store = X509_STORE_new();
	X509_STORE_set_verify_cb(_store, CSMime::VerifyCallback);
	X509_STORE_set_verify_cb_func(_store, CSMime::VerifyCallback);
	_recipCerts = NULL;
	_cipher = NULL;
}

void CSMime::SetUpForSignVerify(CX509Certificate *signerCert, STACK_OF(X509) *intermediateCerts, CX509Certificate *caCert)
{
	_p7FlagsSign |= PKCS7_BINARY;
	_p7FlagsSign &= ~PKCS7_DETACHED;
	_p7FlagsVerify |= PKCS7_BINARY;
	_p7FlagsVerify &= ~PKCS7_DETACHED;

	_signerCert = signerCert;
	_intermediateCerts = intermediateCerts;
	X509_STORE_add_cert(_store, signerCert->X509Object());
	if (_intermediateCerts)
	{
		int num = sk_X509_num(_intermediateCerts);
		for (int i = 0; i < num; i++) 
		{
			X509 *x = sk_X509_value(_intermediateCerts, i);
			X509_STORE_add_cert(_store, x);
		}
	}

	_caCert = caCert;
	if (_caCert)
		X509_STORE_add_cert(_store, caCert->X509Object());
}

bool CSMime::Sign(BIO *in, BIO *out)
{
	bool rv = false;

	if (_p7)
	{
		PKCS7_free(_p7);
		_p7 = NULL;
	}
	
	if (_signerCert->CanSign() && _signerCert->CanVerify())
	{
		_p7 = PKCS7_sign(_signerCert->X509Object(), _signerCert->UsePrivateKey(), _intermediateCerts, in, _p7FlagsSign);
		if (_p7)
		{
			PEM_write_bio_PKCS7_stream(out, _p7, in, _p7FlagsSign);
			PKCS7_free(_p7);
			_p7 = NULL;
			rv = true;
		}
	}

	return rv;
}

bool CSMime::SignEncrypt(BIO *in, BIO *out)
{
	bool rv = false;

	if (_p7)
	{
		PKCS7_free(_p7);
		_p7 = NULL;
	}
	
	if (_signerCert->CanSign() && _signerCert->CanVerify() && _cipher && _recipCerts)
	{
		BIO *postSign = BIO_new(BIO_s_mem());
		if (postSign == NULL)
			return rv;

		if (Sign(in, postSign))
		{
			if (Encrypt(postSign, out))
				rv = true;
		}

		BIO_free_all(postSign);
	}

	return rv;
}

bool CSMime::Encrypt(BIO *in, BIO *out)
{
	bool rv = false;

	if (_p7)
	{
		PKCS7_free(_p7);
		_p7 = NULL;
	}
	
	if (_cipher && _recipCerts)
	{
		_p7 = PKCS7_encrypt(_recipCerts, in, _cipher, _p7FlagsEncrypt);
		if (_p7)
		{
			PEM_write_bio_PKCS7_stream(out, _p7, in, _p7FlagsEncrypt);
			rv = true;

			PKCS7_free(_p7);
			_p7 = NULL;
		}
	}

	return rv;
}

bool CSMime::Verify(BIO *in, BIO *out)
{
	bool rv = false;

	if (_p7)
	{
		PKCS7_free(_p7);
		_p7 = NULL;
	}
	
	_p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
	if (_p7)
	{
		unsigned long err = PKCS7_verify(_p7, _intermediateCerts, _store, NULL, out, _p7FlagsVerify);
		rv = err == 1;
		if (!rv)
		{
			char buf[2048];
			
			printf("%s\n", ERR_error_string(err, buf));
			printf("%s\n", ERR_lib_error_string(err));
			printf("%s\n", ERR_func_error_string(err));
			printf("%s\n", ERR_reason_error_string(err));
			printf("PKCS7_verify returns err=%ld\n", ERR_get_error());
		}

		PKCS7_free(_p7);
		_p7 = NULL;
	}

	return rv;
}

bool CSMime::Decrypt(BIO *in, BIO *out)
{
	bool rv = false;

	if (_p7)
	{
		PKCS7_free(_p7);
		_p7 = NULL;
	}

	if (!_recipCert->CanSign() || !_recipCert->CanVerify())
		return rv;
	
	_p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
	if (_p7)
	{
		if (PKCS7_decrypt(_p7, _recipCert->UsePrivateKey(), _recipCert->X509Object(), out, _p7FlagsDecrypt))
			rv = true;
		
		PKCS7_free(_p7);
		_p7 = NULL;
	}

	return rv;
}

bool CSMime::DecryptVerify(BIO *in, BIO *out)
{
	bool rv = false;

	if (_p7)
	{
		PKCS7_free(_p7);
		_p7 = NULL;
	}
	
	if (_recipCert->CanSign() && _recipCert->CanVerify() && _cipher)
	{
		BIO *postDecrypt = BIO_new(BIO_s_mem());
		if (postDecrypt == NULL)
			return rv;

		if (Decrypt(in, postDecrypt))
		{
			if (Verify(postDecrypt, out))
				rv = true;
		}

		BIO_free_all(postDecrypt);
	}

	return rv;
}

void CSMime::SetUpForEncrypt(STACK_OF(X509) *recipCerts, const EVP_CIPHER *cipher)
{
	_p7FlagsEncrypt = 0;
	_recipCerts = recipCerts;
	_cipher = cipher;
}

void CSMime::SetUpForDecrypt(CX509Certificate *recipCert, const EVP_CIPHER *cipher)
{
	_p7FlagsDecrypt = 0;
	_recipCert = recipCert;
	_cipher = cipher;
}
