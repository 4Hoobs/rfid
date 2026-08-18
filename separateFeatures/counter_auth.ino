#include <MFRC522.h>
#include <SPI.h>
#include <string.h>

#define SS_PIN 10
#define RST_PIN 9

#define MAX_UIDS 100
#define MAX_PSWD_LEN 32
#define MAX_BUFFER_SIZE 64
#define UID_LEN 4

// Counter is stored in block 1 of sector 1 (block 5 absolute)
// Sector 1: blocks 4, 5, 6, 7(trailer)
// We use block 5 for counter storage
#define COUNTER_BLOCK 5
#define MAX_COUNTER_VAL 0xFFFFFFFE

MFRC522 rfid(SS_PIN, RST_PIN);

byte nuidPICC[UID_LEN];

byte UIDs[MAX_UIDS][UID_LEN] = {
    {0x00, 0x00, 0x00, 0x00}
};

// Counter database - mirrors what is stored on each card
// Index matches UIDs array index
uint32_t counterDB[MAX_UIDS] = {0};

unsigned uidCount = 1;

char admin_password[MAX_PSWD_LEN] = "admin";

char serialBuf[MAX_BUFFER_SIZE];
byte serialLen = 0;

// Default auth key - all 0xFF
MFRC522::MIFARE_Key authKey;


// UID management

bool addUID(const byte *a)
{
    if (uidCount >= MAX_UIDS)
        return false;

    for (byte i = 0; i < UID_LEN; i++)
        UIDs[uidCount][i] = a[i];

    counterDB[uidCount] = 0;

    uidCount++;
    return true;
}


bool deleteUID(const byte *a)
{
    int found = -1;

    for (int i = 0; i < uidCount; i++)
    {
        bool same = true;

        for (byte j = 0; j < UID_LEN; j++)
        {
            if (UIDs[i][j] != a[j])
            {
                same = false;
                break;
            }
        }

        if (same)
        {
            found = i;
            break;
        }
    }

    if (found == -1)
        return false;

    for (int i = found; i < uidCount - 1; i++)
    {
        memcpy(UIDs[i], UIDs[i + 1], UID_LEN);
        counterDB[i] = counterDB[i + 1];
    }

    uidCount--;

    memset(UIDs[uidCount], 0, UID_LEN);
    counterDB[uidCount] = 0;

    return true;
}


// UID comparison

bool compareUID(unsigned j)
{
    bool allZero = true;

    for (byte i = 0; i < UID_LEN; i++)
    {
        if (nuidPICC[i] != 0)
        {
            allZero = false;
            break;
        }
    }

    if (allZero)
        return false;

    for (byte i = 0; i < UID_LEN; i++)
    {
        if (UIDs[j][i] != nuidPICC[i])
            return false;
    }

    return true;
}


// Find index of current card in UIDs array
// Returns -1 if not found
int findUID()
{
    for (int i = 0; i < uidCount; i++)
    {
        if (compareUID(i))
            return i;
    }
    return -1;
}


// Counter: read from card memory

bool readCounterFromCard(uint32_t *counter)
{
    MFRC522::StatusCode status = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        COUNTER_BLOCK,
        &authKey,
        &rfid.uid
    );

    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("Counter auth failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }

    byte buf[18];
    byte bufSize = sizeof(buf);

    status = rfid.MIFARE_Read(COUNTER_BLOCK, buf, &bufSize);

    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("Counter read failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }

    // Counter stored as 4 bytes little-endian
    *counter = (uint32_t)buf[0]
             | ((uint32_t)buf[1] << 8)
             | ((uint32_t)buf[2] << 16)
             | ((uint32_t)buf[3] << 24);

    rfid.PCD_StopCrypto1();
    return true;
}


// Counter: write to card memory

bool writeCounterToCard(uint32_t counter)
{
    MFRC522::StatusCode status = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        COUNTER_BLOCK,
        &authKey,
        &rfid.uid
    );

    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("Counter write auth failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }

    byte buf[16] = {0};
    buf[0] = counter & 0xFF;
    buf[1] = (counter >> 8) & 0xFF;
    buf[2] = (counter >> 16) & 0xFF;
    buf[3] = (counter >> 24) & 0xFF;

    status = rfid.MIFARE_Write(COUNTER_BLOCK, buf, 16);

    rfid.PCD_StopCrypto1();

    return status == MFRC522::STATUS_OK;
}


// Counter authentication
// Returns true if counter matches DB, increments both

bool authenticateCounter(int uidIndex)
{
    uint32_t cardCounter = 0;

    if (!readCounterFromCard(&cardCounter))
        return false;

    Serial.print(F("Card counter: "));
    Serial.println(cardCounter);

    Serial.print(F("DB counter:   "));
    Serial.println(counterDB[uidIndex]);

    if (cardCounter != counterDB[uidIndex])
    {
        Serial.println(F("COUNTER MISMATCH - possible cloned card!"));
        return false;
    }

    // Counters match - increment both
    uint32_t newCounter = cardCounter + 1;

    if (newCounter > MAX_COUNTER_VAL)
    {
        Serial.println(F("Counter overflow - re-enroll card"));
        return false;
    }

    counterDB[uidIndex] = newCounter;

    // Re-read card to write updated counter
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(100);

    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial())
    {
        Serial.println(F("Card removed before counter update"));
        // Roll back DB counter since we could not write to card
        counterDB[uidIndex] = cardCounter;
        return false;
    }

    if (!writeCounterToCard(newCounter))
    {
        Serial.println(F("Counter write failed - rolling back"));
        counterDB[uidIndex] = cardCounter;
        return false;
    }

    Serial.print(F("Counter updated to: "));
    Serial.println(newCounter);

    return true;
}


// Serial commands

void handleSerialCommand()
{
    if (serialBuf[0] == '\0')
        return;

    char *token = strtok(serialBuf, " ");

    if (token == nullptr ||
        strcmp(token, admin_password) != 0)
    {
        Serial.println(F("Bad password"));
        serialBuf[0] = '\0';
        delay(1000);
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
                serialBuf[0] = '\0';
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
            serialBuf[0] = '\0';
            return;
        }

        if (strlen(token) < MAX_PSWD_LEN)
        {
            strncpy(
                admin_password,
                token,
                MAX_PSWD_LEN - 1
            );

            admin_password[MAX_PSWD_LEN - 1] = '\0';

            Serial.println(F("Password changed"));
        }
        else
        {
            Serial.println(F("Password too long"));
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
                serialBuf[0] = '\0';
                return;
            }

            b[i] = (byte)strtol(hx, nullptr, 16);
        }

        if (deleteUID(b))
            Serial.println(F("UID deleted"));
        else
            Serial.println(F("Could not delete UID"));
    }

    else
    {
        Serial.println(F("Unknown command"));
    }

    serialBuf[0] = '\0';
}


// Gen1A detection

bool isGen1a()
{
    for (byte attempt = 0; attempt < 3; attempt++)
    {
        if (rfid.MIFARE_OpenUidBackdoor(true))
            return true;

        rfid.PCD_AntennaOff();
        delay(20);
        rfid.PCD_AntennaOn();
        delay(20);
    }

    return false;
}


// Gen2 / CUID detection

bool isGen2Magic()
{
    MFRC522::MIFARE_Key key;

    for (byte i = 0; i < 6; i++)
        key.keyByte[i] = 0xFF;

    MFRC522::PICC_Type piccType =
        rfid.PICC_GetType(rfid.uid.sak);

    if (piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
        piccType != MFRC522::PICC_TYPE_MIFARE_4K)
        return false;

    MFRC522::StatusCode status =
        rfid.PCD_Authenticate(
            MFRC522::PICC_CMD_MF_AUTH_KEY_A,
            0,
            &key,
            &(rfid.uid)
        );

    if (status != MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();
        return false;
    }

    // Read original block 0
    byte block0[18];
    byte bufferSize = sizeof(block0);

    status = rfid.MIFARE_Read(0, block0, &bufferSize);

    if (status != MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();
        return false;
    }

    // Write garbage UID - if card accepts it, it is magic
    byte garbage[16];
    memcpy(garbage, block0, 16);
    garbage[0] = 0xDE;
    garbage[1] = 0xAD;
    garbage[2] = 0xBE;
    garbage[3] = 0xEF;

    status = rfid.MIFARE_Write(0, garbage, 16);

    bool magic = (status == MFRC522::STATUS_OK);

    if (magic)
    {
        // Restore original block 0
        rfid.MIFARE_Write(0, block0, 16);
        Serial.println(F("Block 0 restored"));
    }

    rfid.PCD_StopCrypto1();

    return magic;
}


// UID reading

void readUID()
{
    Serial.print(F("UID: "));

    for (byte i = 0; i < rfid.uid.size; i++)
    {
        if (rfid.uid.uidByte[i] < 0x10)
            Serial.print('0');

        Serial.print(rfid.uid.uidByte[i], HEX);

        if (i < rfid.uid.size - 1)
            Serial.print(' ');
    }

    Serial.println();

    for (byte i = 0; i < UID_LEN; i++)
    {
        if (i < rfid.uid.size)
            nuidPICC[i] = rfid.uid.uidByte[i];
        else
            nuidPICC[i] = 0;
    }
}


// Serial input

void readSerial()
{
    while (Serial.available())
    {
        char c = Serial.read();

        if (c == '\n' || c == '\r')
        {
            if (serialLen > 0)
            {
                serialBuf[serialLen] = '\0';
                serialLen = 0;
            }
        }
        else if (serialLen < MAX_BUFFER_SIZE - 1)
        {
            serialBuf[serialLen++] = c;
        }
    }
}


// Wait for physical card removal

void waitForCardRemoval()
{
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();

    delay(50);

    while (rfid.PICC_IsNewCardPresent())
    {
        delay(50);
    }

    delay(100);
}


// Setup

void setup()
{
    Serial.begin(9600);

    SPI.begin();

    rfid.PCD_SetAntennaGain(MFRC522::RxGain_max);
    rfid.PCD_Init();

    delay(4);

    for (byte i = 0; i < 6; i++)
        authKey.keyByte[i] = 0xFF;

    Serial.println(F("RFID counter auth ready."));
}


// Main loop

void loop()
{
    readSerial();

    if (serialBuf[0] != '\0')
        handleSerialCommand();

    if (!rfid.PICC_IsNewCardPresent())
        return;

    if (!rfid.PICC_ReadCardSerial())
        return;

    readUID();

    delay(20);

    bool gen1a = isGen1a();
    bool gen2 = false;

    if (!gen1a)
    {
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();

        delay(150);

        if (rfid.PICC_IsNewCardPresent() &&
            rfid.PICC_ReadCardSerial())
        {
            gen2 = isGen2Magic();
        }
    }

    if (gen1a)
    {
        Serial.println(F("CARD TYPE: MAGIC GEN1A"));
        Serial.println(F("ACCESS DENIED"));
        waitForCardRemoval();
        return;
    }

    if (gen2)
    {
        Serial.println(F("CARD TYPE: MAGIC GEN2 / CUID"));
        Serial.println(F("ACCESS DENIED"));
        waitForCardRemoval();
        return;
    }

    Serial.println(F("CARD TYPE: STANDARD MIFARE CLASSIC"));

    int uidIndex = findUID();

    if (uidIndex == -1)
    {
        Serial.println(F("UID NOT RECOGNIZED"));
        Serial.println(F("ACCESS DENIED"));
        waitForCardRemoval();
        return;
    }

    Serial.println(F("UID RECOGNIZED"));

    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(150);

    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial())
    {
        Serial.println(F("Card removed too early"));
        return;
    }

    if (authenticateCounter(uidIndex))
    {
        Serial.println(F("COUNTER OK"));
        Serial.println(F("ACCESS GRANTED"));
    }
    else
    {
        Serial.println(F("COUNTER FAIL"));
        Serial.println(F("ACCESS DENIED"));
    }

    waitForCardRemoval();
}
