#include "Padlock.hpp"

static const char * TAG = "Hensor";

Padlock * Padlock::security = nullptr;

Padlock::Padlock() {
	this->clear();
}

inline unsigned long long Padlock::getMessageLength() {
	return this->mlen;
}

bool Padlock::hasSecurity() const {
	if (strlen(this->credentials.ciphertext) > 0) {
		return true;
	}

	return false;
}

void Padlock::clear() {
	sodium_memzero(this->credentials.ciphertext, crypto_secretbox_MACBYTES + this->mlen);
	sodium_memzero(this->credentials.nonce, crypto_secretbox_NONCEBYTES);
}

bool Padlock::pass(const char * newKey, const size_t len, bool settingKey) {
	// Maybe setting key for the first time
	if (settingKey) {
		ESP_LOGI(TAG, "Setting pass for the first time");
		this->setKey(newKey, len);

		return true;
	}

	unsigned char decrypted[this->mlen];
	unsigned char key[crypto_secretbox_KEYBYTES];

	// Preparing key
	sodium_memzero(key, crypto_secretbox_KEYBYTES); // Clear key memory
	memcpy(key, newKey, len); // Filling data

	// Simple comparison between both strings
	if(sodium_memcmp(key, newKey, len) != 0) {
		ESP_LOGE(TAG, "Failed passing keys");
		return false;
	}

	if (crypto_secretbox_open_easy(decrypted, (const unsigned char*) this->ciphertext.c_str(), crypto_secretbox_MACBYTES + this->mlen, (const unsigned char*) this->nonce.c_str(), key) != 0) {
		// message forged!
		ESP_LOGI(TAG, "Message forged");
		return false;
	}

	return true;
}

void Padlock::setKey(const char * newKey, const size_t len) {
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char ciphertext[crypto_secretbox_MACBYTES + this->mlen];

	// Clear memory
	sodium_memzero(ciphertext, crypto_secretbox_MACBYTES + this->mlen);
	sodium_memzero(key, crypto_secretbox_KEYBYTES);

	// Preparing key
	memcpy(key, newKey, len); // Filling data

	// Simple comparison between both strings
	if (sodium_memcmp(key, newKey, len) != 0) {
		ESP_LOGE(TAG, "Failed passing keys");
		return;
	}

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, sizeof nonce);

	crypto_secretbox_easy(ciphertext, this->message, this->mlen, nonce, key);

	this->setCredentials((const char *) ciphertext, (const char *) nonce);
}

inline void Padlock::getCredentials(char * ciphertext, char * nonce) const {
	// Just copying
	memcpy(ciphertext, (const char*) this->credentials.ciphertext, crypto_secretbox_MACBYTES + this->mlen);
	memcpy(nonce, (const char*) this->credentials.nonce, crypto_secretbox_NONCEBYTES);
}

inline void Padlock::setCredentials(const char * ciphertext, const char * nonce) {
	// Saving without care of null terminator because we have the exact space
	memcpy(this->credentials.ciphertext, ciphertext, crypto_secretbox_MACBYTES + this->mlen);
	memcpy(this->credentials.nonce, nonce, crypto_secretbox_NONCEBYTES);
}

Padlock * Padlock::getInstance() {
	if (padlock == nullptr) {
		padlock = new Padlock();
	}

	return padlock;
}
