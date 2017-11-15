#include <cstdlib>
#include <string>
#include <list>
#include <vector>
#include <map>

#include <stdint.h>

#define FORMAT_UNDEF    0
#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define FORMAT_NETSCAPE 4
#define FORMAT_PKCS12   5
#define FORMAT_SMIME    6

#define MD5_HASH_LENGTH		16
#define NETSCAPE_CERT_HDR	"certificate"

#ifdef X509_NAME
#undef X509_NAME
#endif

#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/stack.h>
#include <openssl/md5.h>
#include <openssl/rc4.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#ifndef X509_HPP
#define X509_HPP

#if defined (OPENBSD)
#define PublicKey_digest(data, type, md, len) \
	ASN1_digest ((int (*) (...)) i2d_PublicKey, type, (char *) data, md, len)
#else

#ifdef FC5
#define PublicKey_digest(data, type, md, len) \
	ASN1_digest ((int (*) (void*, unsigned char**)) i2d_PublicKey, type, (char *) data, md, len)
#elif FC9
#define PublicKey_digest(data, type, md, len) \
	ASN1_digest ((int (*) (void*, unsigned char**)) i2d_PublicKey, type, (char *) data, md, len)
#else
#define PublicKey_digest(data, type, md, len) \
	ASN1_digest ((int (*) ()) i2d_PublicKey, type, (char *) data, md, len)
#endif
#endif

const int MD5_HASH_SIZE=16;

typedef unsigned char BYTE;

enum CERT_DATA_ITEMS
{
    KEY_STRENGTH,
    COMMON_NAME,
    COMPANY_NAME,
    COUNTRY_NAME,
	EXPIRATION_DAYS,
	SAVE_FILE,
	SAVE_KEY_FILE
};

enum MESSAGE_DIGEST_TYPE
{
    MD_NONE,
    MD_MD5,
    MD_SHA,
    MD_SHA1,
    MD_DSS,
    MD_DSS1,
    MD_RIPEMD160,
    MD_SHA224,
    MD_SHA256,
    MD_SHA384,
    MD_SHA512
};

class CX509Request;
class CX509Certificate;

class CX509Certificate
{
public:
	static int CertStackToString(STACK_OF(X509) *certs, std::string &buffer, bool noRoot = false);
	static STACK_OF(X509) *CertificatesFromMemory(std::string &buf, bool noRoot = false);
	static STACK_OF(X509) *CertificatesFromFile(std::string &file, bool noRoot = false);
	static STACK_OF(X509) *CertificatesFromFile(int count, ...);
	static STACK_OF(X509) *CertificatesFromCertificate(std::vector<CX509Certificate *> &certs, bool noRoot = false);
	static STACK_OF(X509) *CertificatesFromFile(std::vector<std::string> &files);
	static void ClearStack(STACK_OF(X509) *st);

private:
	X509 *m_x509;
	EVP_MD_CTX *m_mdCtx;
	const EVP_MD *m_mdType;
	unsigned int m_sign;
	unsigned int m_verify;
	EVP_PKEY *m_pkey;

public:
	~CX509Certificate();
	CX509Certificate();
	CX509Certificate(std::string &certFile, int fmt1, std::string &privKeyFile, int fmt2, uint8_t *pswd = NULL);
	CX509Certificate(std::string &certFile, int fmt1);
	CX509Certificate(CX509Request &req, CX509Certificate &caCert, int days, int serial);
	int LoadCert(std::string &file, int format);
	int LoadCertificate(std::string &file, int format);
	int LoadCertInMemory(std::string &incert, int format);
	int LoadKey(std::string &file, int format, uint8_t *paswd = NULL);
	int LoadKeyInMemory(std::string &inkey, int format, uint8_t *pswd = NULL);
	void SignInit(int algo);
	void SignUpdate(unsigned char *data, int count);
	int SignFinal(unsigned char *sign, unsigned int *s);
	void VerifyInit(int algo);
	void VerifyUpdate(unsigned char *data, int count);
	int VerifyFinal(unsigned char *sign, unsigned int s);
	int PublicEncrypt(int flen, unsigned char *from, unsigned char *to, int padding);
	int PublicDecrypt(int flen, unsigned char *from, unsigned char *to, int padding);
	int PrivateEncrypt(int flen, unsigned char *from, unsigned char *to, int padding);
	int PrivateDecrypt(int flen, unsigned char *from, unsigned char *to, int padding);
	EVP_PKEY *ExportPublicKey();
	EVP_PKEY *UsePrivateKey();
	X509 *UseCertificate();
	int SaveCertificate(std::string &file, int outformat);
	int SaveCertToMemory(std::string &buf, int outformat);
	int SavePrivateKey(std::string &file, int outformat, const EVP_CIPHER *cipher = NULL, uint8_t *p = NULL, int klen = 0);
	int SavePrivateKeyToMemory(std::string &buf, int outformat, const EVP_CIPHER *cipher, uint8_t *pass = NULL, int klen = 0);
	int SetCertificate(X509 *x);
	int SetKey(EVP_PKEY *pkey);
	X509_NAME *GetIssuerName();
	X509_NAME *GetSubjectName();
	int SignCert(X509 *x, EVP_MD *md);
	unsigned int GetSerialNumber();
	bool HasExpired();
	int VerifyCA(CX509Certificate &caCert);
	bool IsRevoked();
	bool CanSign();
	bool CanVerify();
	X509 *X509Object();
	void Print();
};

class CX509Request
{
private:
	X509_REQ *m_x509Req;
	EVP_PKEY *m_pkey;
    
public:
	~CX509Request();
	CX509Request();
	CX509Request(std::string &reqFile, int fmt1);
    CX509Request(std::vector<std::string> &args);
	int LoadRequest(std::string &file, int format);
    int CreateRequest(std::vector<std::string> &args);
	int LoadRequestInMemory(std::string &req, int format);
	int SaveRequest(std::string &file, int outformat);
    int SaveRequestToMemory(std::string &buf, int outformat);
	int LoadPrivateKey(std::string &file, int format, uint8_t *pswd = NULL);
	int LoadPrivateKeyInMemory(std::string &inkey, int format, uint8_t *pass = NULL);
	int SavePrivateKey(std::string &file, int outformat, const EVP_CIPHER *cipher = NULL, uint8_t *p = NULL, int klen = 0);
	int SavePrivateKeyToMemory(std::string &buf, int outformat, const EVP_CIPHER *cipher = NULL, uint8_t *pass = NULL, int klen = 0);

	bool VerifyRequest();
	X509_REQ *Request();
	EVP_PKEY *ExportPublicKey();
	EVP_PKEY *UsePrivateKey();
};

class CSMime
{
	public:
		static int VerifyCallback(int ok, X509_STORE_CTX *storeCtx);

	private:
		PKCS7 *_p7;
		int _p7FlagsSign;
		int _p7FlagsVerify;
		int _p7FlagsEncrypt;
		int _p7FlagsDecrypt;
		CX509Certificate *_signerCert;
		CX509Certificate *_caCert;
		STACK_OF(X509) *_intermediateCerts;
		STACK_OF(X509) *_recipCerts;
		CX509Certificate *_recipCert;
		const EVP_CIPHER *_cipher;
		X509_STORE *_store;

	public:
		virtual ~CSMime();
		CSMime();
		void SetUpForSignVerify(CX509Certificate *signerCert, STACK_OF(X509) *intermediateCerts = NULL, CX509Certificate *caCert = NULL);
		bool Sign(BIO *in, BIO *out);
		bool SignEncrypt(BIO *in, BIO *out);
		bool Encrypt(BIO *in, BIO *out);
		bool Verify(BIO *in, BIO *out);
		bool Decrypt(BIO *in, BIO *out);
		bool DecryptVerify(BIO *in, BIO *out);
		void SetUpForEncrypt(STACK_OF(X509) *recipCerts, const EVP_CIPHER *cipher);
		void SetUpForDecrypt(CX509Certificate *recipCert, const EVP_CIPHER *cipher);
};

enum SSLSocketMode
{
	SOCKET_MODE_TCP,
	SOCKET_MODE_UDP
};

class SSLClient
{
	friend void *SSLClientThread(void *arg);
#if 0
	friend void *SSLClientThreadUdp(void *arg);
	friend void *SSLClientJobThread(void *arg);
#endif

	public:
		static unsigned long get_thread_id_cb(void);
		static void thread_lock_cb(int mode, int which, const char * f, int l);
		static int init_ssl_locking(void);
		static void Init();
		static int _ssl_num_locks;
		static pthread_mutex_t *_ssl_locks;
		static pthread_mutex_t _clientJobsMutex;
		static bool _doneInit;

	private:
		pthread_mutex_t _mutex;
		pthread_cond_t _cond;
		std::string _ip;
		short _port;
		SSL_CTX *_ctx;
		SSL *_client_ctx;
		BIO *_udpSbio;
		pthread_t _thread;
		bool _threadRunning;
		bool _terminate;
		int _socket;
		const SSL_METHOD *_method;
		CX509Certificate _sslCert;
		SSLSocketMode _mode;
		std::string _caCertFile;
		bool _ownThread;
		void *_userData;
		void (*_readCallBack)(void *ud, uint8_t *, int);
		pthread_mutex_t _timeoutMutex;
		pthread_cond_t _timeoutCond;
		int _timeout;
	
	private:
		void InitContext();
		bool SocketConnect();

	public:
		virtual ~SSLClient();
		SSLClient(std::string &ip, int port, const SSL_METHOD *method, std::string &sslCertFile, std::string &sslKeyFile, std::string &caCertFile, SSLSocketMode mode = SOCKET_MODE_TCP, 
			bool ownThread = false);
		SSLClient(int sock, const SSL_METHOD *method, std::string &sslCertFile, std::string &sslKeyFile, std::string &caCertFile, SSLSocketMode mode = SOCKET_MODE_TCP, bool ownThread = false);
		bool SSLConnect();
		void Write(uint8_t *buf, int len);
		bool ThreadRunning();
		void ReadCallBack(void (*readCallBack)(void *ud, uint8_t *, int));
		void SetUserData(void *ud);
		void Lock();
		void Wait();
		void Signal();
		void Unlock();
		void LockTimeout();
		void WaitTimeout();
		void SignalTimeout();
		void UnlockTimeout();
};

class WaitingPayload;
#define COOKIE_SECRET_LENGTH    16
#define MAX_TIMEOUT				60
typedef int (*VERIFY_CALLBACK)(int, X509_STORE_CTX *);

class SSLServer
{
	public:
		static pthread_mutex_t *_ssl_locks;
		static int _ssl_num_locks;
		static bool _doneInit;
		static VERIFY_CALLBACK _verifyCallback;
		static uint8_t _cookie_secret[COOKIE_SECRET_LENGTH];
		static int _cookie_initialized;

	public:
		static unsigned long get_thread_id_cb(void);
		static void thread_lock_cb(int mode, int which, const char * f, int l);
		static int init_ssl_locking(void);
		static void Init();
		static void ssl_readcb(struct bufferevent * bev, void * arg);
		static void ssl_eventcb(struct bufferevent * bev, short events, void *arg);
		static void ssl_acceptcb(struct evconnlistener *serv, int sock, struct sockaddr *sa, int sa_len, void *arg);
		static void *SSLServerDispatchThread(void *arg);
		static void *SSLServerUDPThread(void *arg);
		static int VerifyCallback(int ok, X509_STORE_CTX *storeCtx);
		static void SetVerifyCallback(int (*verifyCallback)(int, X509_STORE_CTX *));
		static int GenerateCookieCallback(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
		static int VerifyCookieCallback(SSL *ssl, unsigned char *cookie, unsigned int cookie_len);

	private:
		const SSL_METHOD *_method;
		CX509Certificate _sslCert;
		CX509Certificate _caCert;
		bool _terminate;
		pthread_t _dispatchThread;
		struct event_base *_evbase;
		SSL_CTX *_server_ctx;
		struct evconnlistener *_listener;
		void (*_job)(WaitingPayload *wp, void *ud);
		void (*_jobUDP)(void *ud, uint8_t *data, int len);
		int (*_newClientCallback)(struct sockaddr *, int, void *ud);	
		int (*_sessionEndCallback)(SSL *, void *ud);
		int (*_sessionStartCallback)(SSL *, void *ud);
		bool _valid;
		bool _wantAuth;
		bool _compulsory;
		int _verifyDepth; 
		void *_userData;
		SSLSocketMode _mode;
		std::string _caCertFile;
		SSL *_udpSSL;
		BIO *_udpSbio;
		std::string _udpFrom;
		int _udpSocket;
		int _port;
		pthread_mutex_t _timeoutMutex;
		pthread_cond_t _timeoutCond;
		int _udpTimeout;

	private:
		bool InitContext(std::string &sslCertFile, std::string &sslKeyFile, bool wantAuth, bool compulsory);

	public:
		~SSLServer();
		SSLServer(int port, const SSL_METHOD *method, std::string &sslCertFile, std::string &sslKeyFile, std::string &caCertFile, bool wantAuth = false, bool compulsory = false, 
			int verifyDepth = 1, SSLSocketMode mode = SOCKET_MODE_TCP);
		SSLServer(const SSL_METHOD *method, std::string &sslCertFile, std::string &sslKeyFile, std::string &caCertFile, bool wantAuth = false, bool compulsory = false, 
			int verifyDepth = 1, SSLSocketMode mode = SOCKET_MODE_TCP);
		void SSLUDPLoop();
		bool UDPSSLRead(uint8_t *data, int sz, int *bytes);
		void HandleIncomingData(struct bufferevent *bev);
		int SessionStart(SSL *ssl);
		void HandleConnectionEvents(SSL *s, short events, struct bufferevent *bev);
		bool VerifyPeerCertificate(SSL *ssl);
		void AcceptNewConnection(int sock, struct sockaddr *sa, int sa_len);
		bool WriteBufferSSL(SSL *s, uint8_t *buf, int length);
		bool WriteBufferSSL(uint8_t *buf, int length);
		void Dispatch();
		bool Valid();
		bool Run(int sock = -1);
		void SetResponseCallback(void (*job)(WaitingPayload *, void *));
		void SetUDPResponseCallback(void (*job)(void *, uint8_t *, int));
		void SetNewConnectionCallback(int (*newClientCallback)(struct sockaddr *, int, void *));	
		void SetSessionEndCallback(int (*sessionEndCallback)(SSL *, void *));
		void SetSessionStartCallback(int (*sessionStartCallback)(SSL *, void *));
		void SetUserData(void *ud);
		int SSLHandshakeDone();
		void Lock();
		void Wait();
		void Unlock();
};

#endif
/** Initializing */
void InitCrypto();

/** Endingizing */
void FinishCrypto();

/** Encrypting/Decrypting of data using session key.
ioData is the input data and the encrypted/decrypted data is retrieved from this variable, because of this the memory 
allocation for ioData should be always greater.*/

bool DeriveKey(const EVP_CIPHER *type, const EVP_MD *md, uint8_t *key, uint8_t *iv);
EVP_CIPHER_CTX *InitEncrypt(const EVP_CIPHER *type, ENGINE *impl, uint8_t *key, uint8_t *iv);
EVP_CIPHER_CTX *InitDecrypt(const EVP_CIPHER *type, ENGINE *impl, uint8_t *key, uint8_t *iv);
int UpdateEncrypt(EVP_CIPHER_CTX *ctx, uint8_t **outData, uint8_t *inData, int inLen);
int UpdateDecrypt(EVP_CIPHER_CTX *ctx, uint8_t **outData, uint8_t *inData, int inLen);
int FinalEncrypt(EVP_CIPHER_CTX *ctx, uint8_t **outData);
int FinalDecrypt(EVP_CIPHER_CTX *ctx, uint8_t **outData);
int EncryptDecrypt(int enc, uint8_t *key, uint8_t *iv, uint8_t *originalData, int orgLen, uint8_t **userData);

/** Converting of encrypted data into printable characters */
EVP_ENCODE_CTX *InitEncode();
int UpdateEncode(EVP_ENCODE_CTX *ctx, uint8_t **outData, uint8_t *inData, int inLen);
int FinalEncode(EVP_ENCODE_CTX *ctx, uint8_t **outData);

/** Before Decrypting of Encrypted and Encoded data we have to do reverse of Base64Encode process. */
EVP_ENCODE_CTX *InitDecode();
int UpdateDecode(EVP_ENCODE_CTX *ctx, uint8_t **outData, uint8_t *inData, int inLen);
int FinalDecode(EVP_ENCODE_CTX *ctx, uint8_t **outData);

int EncodeDecode(int enc, uint8_t *originalData, int orgLen, uint8_t **userData);

// Returns 1 if the file name given exists else returns 0
int FileExists(char *file);

