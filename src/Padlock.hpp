#ifndef EFECTIBIT_PADLOCK
#define EFECTIBIT_PADLOCK

/**
 * Security with symmetric key.

 * Variables:
 * K: key
 * Enc: encrypted text
 * Message: "clear_text" (the readable text)

 * New system starts without K.
 * When K is required to be set, that will encrypt Message resulting in Enc.
 * Then Enc is saved in the system.
 * Every time Enc exists in the system and security review is required,
 * K should be required to be inserted and if that decrypts Enc then everything is correct.
 * If the above did not happen then you cannot continue.
 * It is authenticated de/cryption.
 *
 * Don't create many objects, but get the single instance. (Non-thread safe).
 */

#include <sodium.h>

#ifndef PADLOCK_CLEAR_TEXT
	#define PADLOCK_CLEAR_TEXT "padlock"
	#define PADLOCK_CLEAR_TEXT_LENGTH 7
#endif


class Padlock {
	protected:
		Padlock();

		const unsigned char * message = (const unsigned char*) PADLOCK_CLEAR_TEXT;
		unsigned long long mlen = PADLOCK_CLEAR_TEXT_LENGTH;

		static Padlock * padlock;

		struct Credential {
			char ciphertext[crypto_secretbox_MACBYTES + PADLOCK_CLEAR_TEXT_LENGTH];
			char nonce[crypto_secretbox_NONCEBYTES];
		} credential;

	public:
		/**
		 * Simply used to prepare a char * with size.
		 */
		inline unsigned long long getMessageLength();

		/**
		 * Security should not be cloneable.
		 */
		Padlock(Padlock &other) = delete;

		/**
		 * Security should not be assignable.
		 */
		void operator=(const Padlock &) = delete;

		static Padlock * getInstance();

		/**
		 * Clear credentials.
		 */
		void clear();

		/**
		 * Check if there is encrypted text in the system.
		 */
		bool hasSecurity() const;

		/**
		 * Do cryptography for letting to pass or not.
		 */
		bool pass(const char * key, const size_t len, bool settingKey = false);

		/**
		 * It saves encripted message.
		 * Never save key.
		 */
		void setKey(const char * key, const size_t len);

		/**
		 * Get ciphered crediantials in parameters.
		 * Internally the lengths are already known.
		 */
		inline void getCredentials(char * ciphertext, char * nonce) const;

		/**
		 * Store ciphered credentials.
		 */
		inline void setCredentials(const char * ciphertext, const char * nonce);
};

#endif
