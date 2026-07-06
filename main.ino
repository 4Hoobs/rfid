#include<MFRC522.h>
#include <SPI.h>
#include <string.h>
// #include <EEPROM.h>

#define SS_PIN 10
#define RST_PIN 9
#define MAX_UIDS 100
#define MAX_PSWD_LEN 32
#define MAX_BUFFER_SIZE 64
#define UID_LEN 4

// Init array that will store new NUID
byte nuidPICC[UID_LEN];

byte UIDs[MAX_UIDS][UID_LEN] = {{0x0, 0x0, 0x0, 0x0}}; // Where saved UIDs go
unsigned uidCount = 1;                                 // has to be set manually for static UIDs
MFRC522 rfid(SS_PIN, RST_PIN);

char admin_password[MAX_PSWD_LEN] = "admin\0";
char serialBuf[MAX_BUFFER_SIZE];
byte serialLen = 0;

// EEPROM writes/reads
// void loadUIDsFromEEPROM()
// {
//     EEPROM.get(EEPROM_COUNT_ADDR, uidCount);
//     if (uidCount > MAX_UIDS)
//         uidCount = 0; // guard against corrupted/blank EEPROM
//     for (byte i = 0; i < uidCount; i++)
//         EEPROM.get(EEPROM_UIDS_ADDR + i * UID_LEN, UIDs[i]);
// }

// void saveUIDsToEEPROM()
// {
//     EEPROM.put(EEPROM_COUNT_ADDR, uidCount);
//     for (byte i = 0; i < uidCount; i++)
//         EEPROM.put(EEPROM_UIDS_ADDR + i * UID_LEN, UIDs[i]);
// }

// bool addUID(byte a, byte b, byte c, byte d)
// {
//     if (uidCount >= MAX_UIDS)
//         return false;
//     UIDs[uidCount][0] = a;
//     UIDs[uidCount][1] = b;
//     UIDs[uidCount][2] = c;
//     UIDs[uidCount][3] = d;
//     uidCount++;
//     saveUIDsToEEPROM();
//     return true;
// }

bool addUID(const byte *a)
{
    if (uidCount >= MAX_UIDS)
        return false;
    for (size_t i = 0; i < UID_LEN; i++)
    {
        UIDs[uidCount][i] = a[i]
    }
    uidCount++;
    return true;
}
// Remove a UID that matches *a*.
// Returns true if something was removed, false otherwise.
bool deleteUID(const byte *a)
{
    // Find the matching UID
    int found = -1;
    for (int i = 0; i < uidCount; ++i) {
        bool same = true;
        for (size_t j = 0; j < UID_LEN; ++j) {
            if (UIDs[i][j] != a[j]) { same = false; break; }
        }
        if (same) { found = i; break; }
    }

    if (found == -1) return false;   // not found

    // Shift all later UIDs up one slot
    for (int i = found; i < uidCount-1; ++i) {
        memcpy(UIDs[i], UIDs[i+1], UID_LEN);
    }
    uidCount--;          // shrink the list

    // Optional: zero‑out the now-unused last element so it isn’t a “ghost”
    memset(&UIDs[uidCount][0], 0, UID_LEN);

    // Persist if you’re using EEPROM
    // saveUIDsToEEPROM();

    return true;
}


void handleSerialCommand()
{
    char *token = strtok(serialBuf, " ");
    if (token == nullptr || strcmp(token, admin_password) != 0)
    {
        Serial.println(F("Bad password"));
        delay(1000); // crude throttle against brute force
        return;
    }
    token = strtok(NULL, " ");
    if (token != nullptr && strcmp(token, "ADD") == 0)
    {
        byte b[UID_LEN];
        for (byte i = 0; i < UID_LEN; i++)
        {
            char *hx = strtok(NULL, " ");
            if (hx == nullptr)
            {
                Serial.println(F("Bad UID format"));
                return;
            }
            b[i] = (byte)strtol(hx, nullptr, 16);
        }
        if (addUID(b))
            Serial.println(F("UID added"));
        else
            Serial.println(F("Storage full"));
    }
    else if (token != nullptr && strcmp(token, "PSWD") == 0)
    {
        token = strtok(NULL, " ");
        if (token == nullptr)
        {
            Serial.println(F("No new password"));
            return;
        }
        if (strlen(token) < MAX_PSWD_LEN)
        {
            strncpy(admin_password, token, MAX_PSWD_LEN);
        }
    }
    else if (token != nullptr && strcmp(token, "DEL") == 0)
    {
        byte b[UID_LEN];
        for (byte i = 0; i < UID_LEN; i++)
        {
            char *hx = strtok(NULL, " ");
            if (hx == nullptr)
            {
                Serial.println(F("Bad UID format"));
                return;
            }
            b[i] = (byte)strtol(hx, nullptr, 16);
        }
        if (deleteUID(b))
            Serial.println(F("UID deleted"));
        else
            Serial.println(F("Could not delete UID"));
    }
}

// Non-destructive gen1a detection: opens the backdoor auth but does NOT write anything.
bool isGen1a()
{
    MFRC522::StatusCode status = rfid.MIFARE_OpenUidBackdoor(false);
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    return status == MFRC522::STATUS_OK;
}

// Only call this when you deliberately want to reprogram a gen1a card's UID.
bool rewriteUID(byte *newUid, byte size)
{
    bool ok = rfid.MIFARE_SetUid(newUid, size, true);
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    return ok;
}
bool compareUID(unsigned j)
{
    unsigned zeroCount = 0;
    for (size_t i = 0; i < UID_LEN; i++)
    {
        if (UIDs[j][i] != nuidPICC[i])
        {
            return false;
        }
        if (nuidPICC[i] == 0)
        {
            zeroCount++;
        }
        
    }
    // check against all 0 uids
    if (zeroCount == UID_LEN)
    {
        return false;
    }
    
    return true;
}

void readUID()
{
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = rfid.PICC_GetType(rfid.uid.sak);
    Serial.println(rfid.PICC_GetTypeName(piccType));

    // Check is the PICC of Classic MIFARE type
    if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI &&
        piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
        piccType != MFRC522::PICC_TYPE_MIFARE_4K)
    {
        Serial.println(F("Your tag is not of type MIFARE Classic."));
        return;
    }

    // Store NUID into nuidPICC array
    for (byte i = 0; i < UID_LEN; i++)
    {
        nuidPICC[i] = rfid.uid.uidByte[i];
    }

    Serial.println(F("The NUID tag is:"));
    Serial.print(F("In hex: "));
    printHex(rfid.uid.uidByte, rfid.uid.size);
    Serial.println();
    Serial.print(F("In dec: "));
    printDec(rfid.uid.uidByte, rfid.uid.size);
    Serial.println();

    // Halt PICC
    rfid.PICC_HaltA();

    // Stop encryption on PCD
    rfid.PCD_StopCrypto1();
}
/**
 * Helper routine to dump a byte array as hex values to Serial.
 */
void printHex(byte *buffer, byte bufferSize)
{
    for (byte i = 0; i < bufferSize; i++)
    {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

/**
 * Helper routine to dump a byte array as dec values to Serial.
 */
void printDec(byte *buffer, byte bufferSize)
{
    for (byte i = 0; i < bufferSize; i++)
    {
        Serial.print(' ');
        Serial.print(buffer[i], DEC);
    }
}
void readSerial()
{
    while (Serial.available())
    {
        char c = Serial.read();
        if (c == '\n' || c == '\r')
        {
            if (serialLen > 0 && serial)
            {
                serialBuf[serialLen] = '\0';
                serialLen = 0;
            }
        }
        else if (serialLen < MAX_BUFFER_SIZE)
        {
            serialBuf[serialLen++] = c;
        }
    }
}

void setup()
{
    Serial.begin(9600);
    SPI.begin();     // Init SPI bus
    rfid.PCD_Init(); // Init MFRC522
    // loadUIDsFromEEPROM();
}

void loop()
{
    readserial();
    handleSerialCommand();
    // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
    if (!rfid.PICC_IsNewCardPresent())
        return;

    // Verify if the NUID has been read
    if (!rfid.PICC_ReadCardSerial())
        return;
    readUID();

    // restart PICC
    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial())
    {
        return;
    }
    if (!isGen1a())
    {
        bool flag = false;
        for (size_t i = 0; i < uidCount; i++)
        {
            if (compareUID(i))
            {
                Serial.println("RFID card recognized");
                flag = true;
                break;
            }
        }
        if (!flag)
        {
            Serial.println("RFID card *not* recognized");
        }
    }

    delay(100);
}
