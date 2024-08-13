#define PADLOCK_CLEAR_TEXT "clearTextToCipher"
#define PADLOCK_CLEAR_TEXT_LENGTH 17

#include "Padlock.hpp"

#include <Arduino.h>

Padlock * padlock = Padlock::getInstance();

// Array of examples
String pins[] = {"12345", "0123456789", "1234", "$", "1234 5", ""};

void setup() {
	Serial.begin(115200);

	if (!padlock->hasSecurity()) {
		// Use first element of pins as password
		padlock->pass(pins[0].c_str(), pins[0].length(), true);
	}

	for (auto pin : pins) {
		Serial.print("Testing '");
		Serial.print(pin);
		Serial.print("'...");
		if (padlock->pass(pin.c_str(), pin.length())) {
			Serial.print("  OK\n");
		}
		else {
			Serial.print("  FAILED\n");
		}
	}

	Serial.print("\nNow enter the pass and press enter:\n");
}

void loop() {
	if (Serial.available() > 0) {
		String pin = Serial.readString();
		pin.trim(); // remove garbage

		Serial.print("Entered: ");
		Serial.print(pin);
		if (padlock->pass(pin.c_str(), pin.length())) {
			Serial.print("  OK\n");
		}
		else {
			Serial.print("  FAILED\n");
		}
	}
}
