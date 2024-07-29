#define PADLOCK_CLEAR_TEXT "clearTextToCipher"

#include "Padlock.hpp"

Padlock * padlock = Padlock::getInstance();

void setup() {
	if (!padlock->hasSecurity()) {
		padlock->pass("12345", 5, true);
	}
}

void loop() {
	if (Serial.available() > 0) {
		String pin = Serial.readString();

		if (padlock->pass(pin.c_str(), pin.length())) {
			Serial.print("Passed\n");
		}
		else {
			Serial.print("Wrong\n");
		}
	}
}
