#include <cstdlib>
#include <string>
#include <list>
#include <vector>

#include "x509.hpp"

#ifndef CA_HPP
#define CA_HPP

void GeneratePassword(char *pass, int sz);

class CX509Certificate;
class CX509Request;

class CCA
{
private:
    int m_serialNo;
    CX509Certificate *m_caCert;
	std::string m_certFile;
	std::string m_keyFile;
	std::string m_serialFile;
	bool m_valid;

public:
	virtual ~CCA();
	CCA(std::string &serialFile);
	bool GenerateCACert(std::vector <std::string> &args, std::string &pswd);
	bool GenerateCACert(std::vector <std::string> &args);
	bool LoadCACert(std::string &certFile, std::string &keyFile, std::string &pswd);
	CX509Certificate *Certificate();
	CX509Certificate *GenerateCertificate(CX509Request &req, int days);
	
	std::string GetCertFile();
	std::string GetKeyFile();
	bool IsValid();
};

#endif
