#include "pgp_wrapper.h"
#include <pgpEncode.h>
#include <pgpErrors.h>
#include <pgpUtilities.h>
#include <pgpConfig.h>
#include <pgpKeys.h>
#include <pgpRandomPool.h>
#include <fstream>
#include <ctime>
#include <string>
#include <sstream>
#include <unordered_map>
#include <cstring>
#include <iostream>
#include <direct.h>
#include <windows.h>
#include <cstdlib>

static PGPContextRef m_PGPContext = kInvalidPGPContextRef;

std::string KEY_FILE;
std::string ENCRYPTION_KEY_ID;
std::string DECRYPTION_PASSWORD;

std::unordered_map<std::string, std::string> load_config(const std::string& filename) {
	std::unordered_map<std::string, std::string> config;
	std::ifstream file(filename);
	std::string line;

	while (std::getline(file, line)) {
		std::istringstream is_line(line);
		std::string key;
		if (std::getline(is_line, key, '=')) {
			std::string value;
			if (std::getline(is_line, value)) {
				config[key] = value;
			}
		}
	}
	return config;
}

void log_message(const std::string& message) {
	std::ofstream log_file("pgp_log.txt", std::ios::app);
	if (log_file.is_open()) {
		std::time_t now = std::time(nullptr);
		char timeStr[26];
		ctime_s(timeStr, sizeof(timeStr), &now);

		size_t len = std::strlen(timeStr);
		if (len > 0 && timeStr[len - 1] == '\n') {
			timeStr[len - 1] = '\0';
		}

		log_file << timeStr << ": " << message << std::endl;
	}
}

void feed_entropy_pool(int count = 100) {
	std::srand(static_cast<unsigned int>(std::time(nullptr)));

	for (int i = 0; i < count; ++i) {
		char simulatedKey = static_cast<char>(33 + std::rand() % 94);
		PGPGlobalRandomPoolAddKeystroke(simulatedKey);
	}
}



bool initialize_pgp() {
	char exePath[MAX_PATH];
	GetModuleFileNameA(NULL, exePath, MAX_PATH);
	std::string basePath(exePath);
	basePath = basePath.substr(0, basePath.find_last_of("\\/"));

	std::string configPath = basePath + "\\pgp_config.cfg";
	auto config = load_config(configPath);

	KEY_FILE = basePath + "\\" + config["key_file"];
	ENCRYPTION_KEY_ID = config["encryption_key_id"];
	DECRYPTION_PASSWORD = config["decryption_password"];

	char fullPrimary[MAX_PATH];
	_fullpath(fullPrimary, KEY_FILE.c_str(), MAX_PATH);
	log_message("Resolved KEY_FILE: " + std::string(fullPrimary));

	// Initializing PGP context if is not already active
	if (PGPContextRefIsValid(m_PGPContext)) return true;

	PGPError err = PGPsdkInit();
	if (!IsPGPError(err)) {
		err = PGPNewContext(kPGPsdkAPIVersion, &m_PGPContext);
	}

	return !IsPGPError(err);
}


std::string encrypt_text(const std::string& plain_text) {
	if (!initialize_pgp()) return "PGP init failed";

	std::string keyFilePath = KEY_FILE;  // Ruta al archivo .asc
	PGPKeySetRef importedKeySet = kInvalidPGPKeySetRef;
	PGPFileSpecRef keyFileSpec = kInvalidPGPFileSpecRef;
	PGPFilterRef filter = kInvalidPGPFilterRef;
	PGPKeySetRef foundUserKeys = kInvalidPGPKeySetRef;
	std::string encrypted;
	char* buffer = nullptr;
	unsigned long bufLen = 4000;
	PGPSize actLen = 0;

	PGPError err = PGPNewFileSpecFromFullPath(m_PGPContext, keyFilePath.c_str(), &keyFileSpec);
	if (!IsPGPError(err)) {
		PGPError err = PGPImportKeySet(
			m_PGPContext,
			&importedKeySet,
			PGPOInputFile(m_PGPContext, keyFileSpec),
			PGPOLastOption(m_PGPContext)
			);
	}

	if (!IsPGPError(err)) {
		err = PGPNewUserIDStringFilter(m_PGPContext, ENCRYPTION_KEY_ID.c_str(), kPGPMatchSubString, &filter);
	}

	if (!IsPGPError(err)) {
		err = PGPFilterKeySet(importedKeySet, filter, &foundUserKeys);
	}

	PGPUInt32 actualEntropy = PGPGlobalRandomPoolGetEntropy();
	PGPUInt32 minimunEntropy = PGPGlobalRandomPoolGetMinimumEntropy();
	
	while (actualEntropy < minimunEntropy)
	{
		log_message("Not enough entropy to encrypt.");
		log_message("Minimun Entropy Needed: " + std::to_string(minimunEntropy) + " - Current Entropy: " + std::to_string(actualEntropy));
		log_message("Generating new entropy.");
		feed_entropy_pool();
	
		actualEntropy = PGPGlobalRandomPoolGetEntropy();
		minimunEntropy = PGPGlobalRandomPoolGetMinimumEntropy();
	}
	
	log_message("Enough entropy genearted to encrypt.");
	log_message("Minimun Entropy Needed: " + std::to_string(minimunEntropy) + " - Current Entropy: " + std::to_string(actualEntropy));
	
	log_message("Starting encryption...");
	while (true) {
		buffer = new char[bufLen];
		err = PGPEncode(m_PGPContext,
			PGPOEncryptToKeySet(m_PGPContext, foundUserKeys),
			PGPOInputBuffer(m_PGPContext, plain_text.c_str(), plain_text.length()),
			PGPOArmorOutput(m_PGPContext, true),
			PGPOCompression(m_PGPContext, true),
			PGPOOutputBuffer(m_PGPContext, buffer, bufLen, &actLen),
			PGPOLastOption(m_PGPContext));
	
		if (!IsPGPError(err)) {
			encrypted.assign(buffer, actLen);
			log_message("Encryption was successful.");
			delete[] buffer;
			buffer = nullptr;
			break;
		}
		else if (err == kPGPError_OutputBufferTooSmall) {
			log_message("Output buffer too small. Resizing to: " + std::to_string(actLen));
			delete[] buffer;
			buffer = nullptr;
			bufLen = actLen;
		}
		else {
			log_message("PGPEncode failed with error: " + std::to_string(err));
			delete[] buffer;
			buffer = nullptr;
			break;
		}
	}		

	// Free resources
	if (PGPFileSpecRefIsValid(keyFileSpec)) PGPFreeFileSpec(keyFileSpec);
	if (PGPKeySetRefIsValid(importedKeySet)) PGPFreeKeySet(importedKeySet);
	if (PGPKeySetRefIsValid(foundUserKeys)) PGPFreeKeySet(foundUserKeys);
	if (PGPFilterRefIsValid(filter)) PGPFreeFilter(filter);

	return IsPGPError(err) ? "Encryption failed" : encrypted;
}




std::string decrypt_text(const std::string& encrypted_text) {
	if (!initialize_pgp()) return "PGP init failed";

	std::string keyFilePath = KEY_FILE;  // Ruta al archivo .asc
	PGPKeySetRef importedKeySet = kInvalidPGPKeySetRef;
	PGPFileSpecRef keyFileSpec = kInvalidPGPFileSpecRef;
	PGPKeyListRef keyList = kInvalidPGPKeyListRef;
	PGPKeyIterRef keyIter = kInvalidPGPKeyIterRef;
	PGPKeyRef privateKey = kInvalidPGPKeyRef;
	std::string decrypted;
	char* buffer = nullptr;
	unsigned long bufLen = 4096;
	PGPSize actLen = 0;
	PGPError err = kPGPError_NoErr;

	// Creating FileSpec
	err = PGPNewFileSpecFromFullPath(m_PGPContext, keyFilePath.c_str(), &keyFileSpec);
	if (IsPGPError(err)) {
		log_message("Failed to create file spec for key file.");
		return "FileSpec error";
	}

	// Importing key
	err = PGPImportKeySet(
		m_PGPContext,
		&importedKeySet,
		PGPOInputFile(m_PGPContext, keyFileSpec),
		PGPOLastOption(m_PGPContext)
		);
	if (IsPGPError(err)) {
		log_message("PGPImportKeySet failed with error: " + std::to_string(err));
		return "Key import failed";
	}

	// Ordering keys to iterate
	err = PGPOrderKeySet(importedKeySet, kPGPKeyOrdering_force, &keyList);
	if (IsPGPError(err)) {
		log_message("Failed to order key set.");
		return "Key ordering failed";
	}
	
	err = PGPNewKeyIter(keyList, &keyIter);
	if (IsPGPError(err)) {
		log_message("Failed to create key iterator.");
		return "Iterator creation failed";
	}

	// Seeking for a valid private key
	while (PGPKeyIterNext(keyIter, &privateKey) == kPGPError_NoErr) {
		PGPBoolean isSecret = false;
		err = PGPGetKeyBoolean(privateKey, kPGPKeyPropIsSecret, &isSecret);
		if (!IsPGPError(err) && isSecret) {
			log_message("Found secret key. Verifying passphrase...");
			if (PGPPassphraseIsValid(
				privateKey,
				PGPOPassphrase(m_PGPContext, DECRYPTION_PASSWORD.c_str()),
				PGPOLastOption(m_PGPContext)))
			{
				log_message("Passphrase is valid.");
				break;
			}
			else {
				log_message("Passphrase is invalid for this key.");
			}

		}
	}

	if (!PGPKeyRefIsValid(privateKey)) {
		log_message("No valid private key found with matching passphrase.");
		return "Invalid passphrase or no private key";
	}

	// Decode
	buffer = new(std::nothrow) char[bufLen];
	if (!buffer) {
		log_message("Memory allocation failed.");
		return "Memory error";
	}

	err = PGPDecode(
		m_PGPContext,
		PGPOInputBuffer(m_PGPContext, encrypted_text.c_str(), encrypted_text.length()),
		PGPOOutputBuffer(m_PGPContext, buffer, bufLen, &actLen),
		PGPOKeySetRef(m_PGPContext, importedKeySet),
		PGPOPassphrase(m_PGPContext, DECRYPTION_PASSWORD.c_str()),
		PGPOLastOption(m_PGPContext)
		);

	if (!IsPGPError(err) && actLen > 0) {
		decrypted.assign(buffer, actLen);
		log_message("Decryption successful. Bytes decrypted: " + std::to_string(actLen));
	}
	else {
		log_message("Decryption failed or produced no output. Error: " + std::to_string(err));
	}

	delete[] buffer;

	// Free resources
	if (PGPFileSpecRefIsValid(keyFileSpec)) PGPFreeFileSpec(keyFileSpec);
	if (PGPKeySetRefIsValid(importedKeySet)) PGPFreeKeySet(importedKeySet);
	if (PGPKeyListRefIsValid(keyList)) PGPFreeKeyList(keyList);

	return IsPGPError(err) || actLen == 0 ? "Decryption failed" : decrypted;
}
