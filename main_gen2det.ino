
#include <MFRC522.h>
#include <SPI.h>
#include <string.h>

#define SS_PIN 10
#define RST_PIN 9

#define MAX_UIDS 100
#define MAX_PSWD_LEN 32
#define MAX_BUFFER_SIZE 64
#define UID_LEN 4

MFRC522 rfid(SS_PIN, RST_PIN);

byte nuidPICC[UID_LEN];

byte UIDs[MAX_UIDS][UID_LEN] = {
    {0x00, 0x00, 0x00, 0x00}};

unsigned uidCount = 1;

char admin_password[MAX_PSWD_LEN] = "admin";

char serialBuf[MAX_BUFFER_SIZE];
byte serialLen = 0;

bool addUID(const byte *a)
{
    if (uidCount >= MAX_UIDS)
        return false;

    for (byte i = 0; i < UID_LEN; i++)
    {
        UIDs[uidCount][i] = a[i];
    }

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
        memcpy(
            UIDs[i],
            UIDs[i + 1],
            UID_LEN);
    }

    uidCount--;

    memset(
        UIDs[uidCount],
        0,
        UID_LEN);

    return true;
}

void handleSerialCommand()
{
    if (serialBuf[0] == '\0')
        return;

    char *token = strtok(
        serialBuf,
        " ");

    if (token == nullptr ||
        strcmp(token, admin_password) != 0)
    {
        Serial.println(
            F("Bad password"));

        serialBuf[0] = '\0';

        delay(1000);

        return;
    }

    token = strtok(
        NULL,
        " ");

    if (token != nullptr &&
        strcmp(token, "ADD") == 0)
    {
        byte b[UID_LEN];

        for (byte i = 0; i < UID_LEN; i++)
        {
            char *hx = strtok(
                NULL,
                " ");

            if (hx == nullptr)
            {
                Serial.println(
                    F("Bad UID format"));

                serialBuf[0] = '\0';

                return;
            }

            b[i] = (byte)strtol(
                hx,
                nullptr,
                16);
        }

        if (addUID(b))
        {
            Serial.println(
                F("UID added"));
        }
        else
        {
            Serial.println(
                F("Storage full"));
        }
    }
    else if (
        token != nullptr &&
        strcmp(token, "PSWD") == 0)
    {
        token = strtok(
            NULL,
            " ");

        if (token == nullptr)
        {
            Serial.println(
                F("No new password"));

            serialBuf[0] = '\0';

            return;
        }

        if (strlen(token) < MAX_PSWD_LEN)
        {
            strncpy(
                admin_password,
                token,
                MAX_PSWD_LEN - 1);

            admin_password[MAX_PSWD_LEN - 1] = '\0';

            Serial.println(
                F("Password changed"));
        }
        else
        {
            Serial.println(
                F("Password too long"));
        }
    }
    else if (
        token != nullptr &&
        strcmp(token, "DEL") == 0)
    {
        byte b[UID_LEN];

        for (byte i = 0; i < UID_LEN; i++)
        {
            char *hx = strtok(
                NULL,
                " ");

            if (hx == nullptr)
            {
                Serial.println(
                    F("Bad UID format"));

                serialBuf[0] = '\0';

                return;
            }

            b[i] = (byte)strtol(
                hx,
                nullptr,
                16);
        }

        if (deleteUID(b))
        {
            Serial.println(
                F("UID deleted"));
        }
        else
        {
            Serial.println(
                F("Could not delete UID"));
        }
    }
    else
    {
        Serial.println(
            F("Unknown command"));
    }

    serialBuf[0] = '\0';
}

bool isGen1a()
{
    bool isGen1a()
    {
        for (byte attempt = 0; attempt < 3; attempt++)
        {
            if (rfid.MIFARE_OpenUidBackdoor(true))
            {
                return true;
            }

            rfid.PCD_AntennaOff();
            delay(20); // maybe should be increased?
            rfid.PCD_AntennaOn();
            delay(20);
        }
        return false;
    }
}

bool isGen2Magic()
{
    MFRC522::MIFARE_Key key;

    for (byte i = 0; i < 6; i++)
    {
        key.keyByte[i] = 0xFF;
    }

    MFRC522::PICC_Type piccType =
        rfid.PICC_GetType(
            rfid.uid.sak);

    if (piccType !=
            MFRC522::PICC_TYPE_MIFARE_1K &&
        piccType !=
            MFRC522::PICC_TYPE_MIFARE_4K)
    {
        return false;
    }

    MFRC522::StatusCode status =
        rfid.PCD_Authenticate(
            MFRC522::PICC_CMD_MF_AUTH_KEY_A,
            0,
            &key,
            &(rfid.uid));

    if (status !=
        MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();

        return false;
    }

    byte block0[18];
    byte bufferSize = sizeof(block0);

    status =
        rfid.MIFARE_Read(
            0,
            block0,
            &bufferSize);

    if (status !=
        MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();

        return false;
    }

    status =
        rfid.MIFARE_Write(
            0,
            block0,
            16);

    rfid.PCD_StopCrypto1();

    return status ==
           MFRC522::STATUS_OK;
}

bool rewriteUID(
    byte *newUid,
    byte size)
{
    bool ok =
        rfid.MIFARE_SetUid(
            newUid,
            size,
            true);

    rfid.PICC_HaltA();

    rfid.PCD_StopCrypto1();

    return ok;
}

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
        {
            return false;
        }
    }

    return true;
}

void readUID()
{
    Serial.print(
        F("PICC type: "));

    MFRC522::PICC_Type piccType =
        rfid.PICC_GetType(
            rfid.uid.sak);

    Serial.println(
        rfid.PICC_GetTypeName(
            piccType));

    Serial.print(
        F("UID: "));

    printHex(
        rfid.uid.uidByte,
        rfid.uid.size);

    Serial.println();

    Serial.print(
        F("UID decimal: "));

    printDec(
        rfid.uid.uidByte,
        rfid.uid.size);

    Serial.println();

    for (byte i = 0; i < UID_LEN; i++)
    {
        if (i < rfid.uid.size)
        {
            nuidPICC[i] =
                rfid.uid.uidByte[i];
        }
        else
        {
            nuidPICC[i] = 0;
        }
    }
}

void printHex(
    byte *buffer,
    byte bufferSize)
{
    for (byte i = 0;
         i < bufferSize;
         i++)
    {
        if (buffer[i] < 0x10)
            Serial.print("0");

        Serial.print(
            buffer[i],
            HEX);

        if (i < bufferSize - 1)
            Serial.print(" ");
    }
}

void printDec(
    byte *buffer,
    byte bufferSize)
{
    for (byte i = 0;
         i < bufferSize;
         i++)
    {
        Serial.print(
            buffer[i],
            DEC);

        if (i < bufferSize - 1)
            Serial.print(" ");
    }
}

void readSerial()
{
    while (Serial.available())
    {
        char c =
            Serial.read();

        if (c == '\n' ||
            c == '\r')
        {
            if (serialLen > 0)
            {
                serialBuf[serialLen] =
                    '\0';

                serialLen = 0;
            }
        }
        else if (
            serialLen <
            MAX_BUFFER_SIZE - 1)
        {
            serialBuf[serialLen++] =
                c;
        }
    }
}

void setup()
{
    Serial.begin(9600);

    SPI.begin();

    rfid.PCD_SetAntennaGain(MFRC522::RxGain_max);
    rfid.PCD_Init();

    delay(4);

    Serial.println(
        F("RFID reader ready."));
}

void loop()
{
    readSerial();

    if (serialBuf[0] != '\0')
    {
        handleSerialCommand();
    }

    if (!rfid.PICC_IsNewCardPresent())
        return;

    if (!rfid.PICC_ReadCardSerial())
        return;

    readUID();
    delay(20);

    bool gen1a =
        isGen1a();

    bool gen2 = false;

    if (!gen1a)
    {
        delay(50);
        if (rfid.PICC_IsNewCardPresent() &&
            rfid.PICC_ReadCardSerial())
        {
            gen2 =
                isGen2Magic();
        }
    }

    Serial.println();

    if (gen1a)
    {
        Serial.println(
            F("CARD TYPE: MAGIC GEN1A"));

        Serial.println(
            F("UID REWRITING: SUPPORTED"));
    }
    else if (gen2)
    {
        Serial.println(
            F("CARD TYPE: MAGIC GEN2 / CUID"));

        Serial.println(
            F("UID REWRITING: SUPPORTED"));
    }
    else
    {
        Serial.println(
            F("CARD TYPE: STANDARD MIFARE CLASSIC"));

        Serial.println(
            F("UID REWRITING: NOT DETECTED"));
    }

    bool recognized = false;

    for (size_t i = 0;
         i < uidCount;
         i++)
    {
        if (compareUID(i))
        {
            recognized = true;
            break;
        }
    }

    if (recognized)
    {
        Serial.println(
            F("RFID card recognized"));
    }
    else
    {
        Serial.println(
            F("RFID card NOT recognized"));
    }

    rfid.PICC_HaltA();

    rfid.PCD_StopCrypto1();

    delay(100);
}
