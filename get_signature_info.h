#pragma once

#include "signature_verification.h"
#include "cert_analyzer.h"

/* self-defined return data structure */
struct SIGN_DATA {
	BOOL signature; // certificate signed by trusted root certificate in the whitelist
	std::string SubjectName;
	std::string IssuerName;
	std::string Version;
	std::string Serial;
	std::string Thumbprint;
	std::string NotBefore;
	std::string NotAfter;
	std::string SignAlgorithm;
	std::string CRLpoint;
	int SubjectPublicKeyLength;
	std::string SubjectPublicKey;
};


SIGN_DATA GetSignatureInfo(std::string filePath);
