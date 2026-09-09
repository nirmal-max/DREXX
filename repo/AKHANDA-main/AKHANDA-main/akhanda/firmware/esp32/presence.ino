/*
 * ESP32 WROOM, Presence Confirmation Device
 * OWNER: lead
 *
 * Role: prove a human is physically present at a separate device before a signature is
 * issued. Receives an entry-hash prefix over serial, waits for a physical button press,
 * returns a confirmation token. This is PRESENCE ONLY. This device does NOT store keys
 * securely (CVE-2019-17391). Do not describe it as a secure element.
 *
 * Wiring: push button between GPIO 0 and GND (uses internal pullup).
 * Optional: small OLED to show the prefix awaiting confirmation.
 */

const int BUTTON_PIN = 0;
String pending = "";

void setup() {
  Serial.begin(115200);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
}

void loop() {
  // Workstation sends: "REQ <hash_prefix>\n"
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.startsWith("REQ ")) {
      pending = line.substring(4);
      Serial.println("WAITING " + pending);   // show we are awaiting a press
    }
  }

  // On physical press, confirm the pending request.
  if (pending.length() > 0 && digitalRead(BUTTON_PIN) == LOW) {
    delay(30);                                  // debounce
    if (digitalRead(BUTTON_PIN) == LOW) {
      Serial.println("CONFIRMED " + pending);   // token the client parses
      pending = "";
      while (digitalRead(BUTTON_PIN) == LOW) {} // wait for release
    }
  }
}
