#ifndef RFID_H
#define RFID_H

#include <MFRC522.h>
#include <SPI.h>

extern MFRC522 rfid;          // defined in RFID.cpp

// UID storage – keep it public if you want to access it from the sketch,
// or wrap it inside a class/struct.
extern byte UIDs[MAX_UIDS][UID_LEN];
extern unsigned uidCount;

// Public API
bool addUID(const byte *uid);
bool deleteUID(const byte *uid);
void readUID();
bool isGen1a();
bool rewriteUID(byte *newUid, byte size);

#endif // RFID_H
