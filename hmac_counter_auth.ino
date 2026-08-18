#include <MFRC522.h>
#include <SPI.h>
#include <string.h>

#define SS_PIN 10
#define RST_PIN 9

#define MAX_UIDS 100
#define MAX_PSWD_LEN 32
#define MAX_BUFFER_SIZE 64
#define UID_LEN 4

// HMAC secret key - change this to your own secret!
// This is stored ONLY on the reader, never on the card
#define HMAC_KEY "SuperSecretRFIDKey2024"
#define HMAC_KEY_LEN 22

// Card memory layout (sector 1: blocks 4, 5, 6, 7=trailer)
// Block 4: 4-byte counter (little-endian) + 12 bytes padding
// Block 5: first 16 bytes of HMAC-SHA256(key, UID || counter)
// Block 6: last 16 bytes of that tag
#define COUNTER_BLOCK 4
#define TAG_BLOCK_A   5
#define TAG_BLOCK_B   6
#define MAX_COUNTER_VAL 0xFFFFFFFE

MFRC522 rfid(SS_PIN, RST_PIN);

byte nuidPICC[UID_LEN];

byte UIDs[MAX_UIDS][UID_LEN] = {
    {0x00, 0x00, 0x00, 0x00}
};

// Counter database - mirrors the last-accepted counter for each UID
// Index matches UIDs array index
uint32_t counterDB[MAX_UIDS] = {0};

unsigned uidCount = 1;

char admin_password[MAX_PSWD_LEN] = "admin";

char serialBuf[MAX_BUFFER_SIZE];
byte serialLen = 0;

// Default auth key - all 0xFF
MFRC522::MIFARE_Key authKey;


// --------------------------------------------------
// Cryptography
// --------------------------------------------------

// SHA256 implementation (public domain, Brad Conte)

typedef struct {
    byte data[64];
    uint32_t datalen;
    uint32_t bitlen[2];
    uint32_t state[8];
} SHA256_CTX;

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)     (ROTRIGHT(x,2)  ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x)     (ROTRIGHT(x,6)  ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x)    (ROTRIGHT(x,7)  ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x)    (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

void sha256_transform(SHA256_CTX *ctx, const byte *data)
{
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];

    for (i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = ((uint32_t)data[j] << 24)
             | ((uint32_t)data[j+1] << 16)
             | ((uint32_t)data[j+2] << 8)
             | ((uint32_t)data[j+3]);

    for (; i < 64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a=ctx->state[0]; b=ctx->state[1];
    c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5];
    g=ctx->state[6]; h=ctx->state[7];

    for (i = 0; i < 64; i++)
    {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b;
    ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f;
    ctx->state[6]+=g; ctx->state[7]+=h;
}

void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen   = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->state[0]  = 0x6a09e667;
    ctx->state[1]  = 0xbb67ae85;
    ctx->state[2]  = 0x3c6ef372;
    ctx->state[3]  = 0xa54ff53a;
    ctx->state[4]  = 0x510e527f;
    ctx->state[5]  = 0x9b05688c;
    ctx->state[6]  = 0x1f83d9ab;
    ctx->state[7]  = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const byte *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        if (ctx->datalen == 64)
        {
            sha256_transform(ctx, ctx->data);
            ctx->datalen = 0;

            if ((ctx->bitlen[0] += 512) < 512)
                ctx->bitlen[1]++;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, byte *hash)
{
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else
    {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen[0] += ctx->datalen * 8;
    if (ctx->bitlen[0] < ctx->datalen * 8)
        ctx->bitlen[1]++;

    ctx->data[63] = ctx->bitlen[0];
    ctx->data[62] = ctx->bitlen[0] >> 8;
    ctx->data[61] = ctx->bitlen[0] >> 16;
    ctx->data[60] = ctx->bitlen[0] >> 24;
    ctx->data[59] = ctx->bitlen[1];
    ctx->data[58] = ctx->bitlen[1] >> 8;
    ctx->data[57] = ctx->bitlen[1] >> 16;
    ctx->data[56] = ctx->bitlen[1] >> 24;

    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++)
    {
        hash[i]    = (ctx->state[0] >> (24-i*8)) & 0xFF;
        hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0xFF;
        hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0xFF;
        hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0xFF;
        hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0xFF;
        hash[i+20] = (ctx->state[5] >> (24-i*8)) & 0xFF;
        hash[i+24] = (ctx->state[6] >> (24-i*8)) & 0xFF;
        hash[i+28] = (ctx->state[7] >> (24-i*8)) & 0xFF;
    }
}


// HMAC-SHA256

void hmacSHA256(
    const byte *key,  byte keyLen,
    const byte *msg,  byte msgLen,
    byte *outHash)
{
    byte ipad[64];
    byte opad[64];
    byte innerHash[32];

    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    for (byte i = 0; i < keyLen; i++)
    {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, msg, msgLen);
    sha256_final(&ctx, innerHash);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, innerHash, 32);
    sha256_final(&ctx, outHash);
}


// Compute expected tag for current card UID + a given counter value
// message = UID (4 bytes) || counter (4 bytes, little-endian)

void computeExpectedTag(uint32_t counter, byte *outHash)
{
    byte msg[8];

    memcpy(msg, nuidPICC, UID_LEN);

    msg[4] = counter & 0xFF;
    msg[5] = (counter >> 8) & 0xFF;
    msg[6] = (counter >> 16) & 0xFF;
    msg[7] = (counter >> 24) & 0xFF;

    hmacSHA256(
        (const byte *)HMAC_KEY,
        HMAC_KEY_LEN,
        msg,
        8,
        outHash
    );
}

// --------------------------------------------------
// UID management
// --------------------------------------------------
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

// --------------------------------------------------
// Non-magic card I/O
// --------------------------------------------------

// Card data: read counter + tag (blocks 4, 5, 6 - one sector-level auth covers all three)

bool readCardData(uint32_t *counter, byte *tag)
{
    MFRC522::StatusCode status = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        COUNTER_BLOCK,
        &authKey,
        &rfid.uid
    );

    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("Auth failed"));
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

    *counter = (uint32_t)buf[0]
             | ((uint32_t)buf[1] << 8)
             | ((uint32_t)buf[2] << 16)
             | ((uint32_t)buf[3] << 24);

    bufSize = sizeof(buf);
    status = rfid.MIFARE_Read(TAG_BLOCK_A, buf, &bufSize);
    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("Tag read (A) failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }
    memcpy(tag, buf, 16);

    bufSize = sizeof(buf);
    status = rfid.MIFARE_Read(TAG_BLOCK_B, buf, &bufSize);
    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("Tag read (B) failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }
    memcpy(tag + 16, buf, 16);

    rfid.PCD_StopCrypto1();
    return true;
}


// Card data: write counter + tag (blocks 4, 5, 6)

bool writeCardData(uint32_t counter, const byte *tag)
{
    MFRC522::StatusCode status = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        COUNTER_BLOCK,
        &authKey,
        &rfid.uid
    );

    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("Write auth failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }

    byte buf[16] = {0};
    buf[0] = counter & 0xFF;
    buf[1] = (counter >> 8) & 0xFF;
    buf[2] = (counter >> 16) & 0xFF;
    buf[3] = (counter >> 24) & 0xFF;

    status = rfid.MIFARE_Write(COUNTER_BLOCK, buf, 16);
    if (status != MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();
        return false;
    }

    memcpy(buf, tag, 16);
    status = rfid.MIFARE_Write(TAG_BLOCK_A, buf, 16);
    if (status != MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();
        return false;
    }

    memcpy(buf, tag + 16, 16);
    status = rfid.MIFARE_Write(TAG_BLOCK_B, buf, 16);

    rfid.PCD_StopCrypto1();

    return status == MFRC522::STATUS_OK;
}


// Combined authentication
// 1. Tag must be a valid HMAC over (UID || card's counter) - proves the card
//    wasn't just written to with a guessed/stale counter using the known
//    default sector key.
// 2. Counter must match what the reader last accepted for this UID - proves
//    this isn't a replay of an old (counter, tag) snapshot.
// Only if both hold do we advance the counter and re-sign the card.

bool authenticateCombined(int uidIndex)
{
    uint32_t cardCounter = 0;
    byte cardTag[32];

    if (!readCardData(&cardCounter, cardTag))
        return false;

    byte expectedTag[32];
    computeExpectedTag(cardCounter, expectedTag);

    byte diff = 0;
    for (byte i = 0; i < 32; i++)
        diff |= (cardTag[i] ^ expectedTag[i]);

    if (diff != 0)
    {
        Serial.println(F("TAG INVALID - card not enrolled or tampered"));
        return false;
    }

    Serial.print(F("Card counter: "));
    Serial.println(cardCounter);

    Serial.print(F("DB counter:   "));
    Serial.println(counterDB[uidIndex]);

    if (cardCounter != counterDB[uidIndex])
    {
        Serial.println(F("COUNTER MISMATCH - possible cloned/replayed card!"));
        return false;
    }

    uint32_t newCounter = cardCounter + 1;

    if (newCounter > MAX_COUNTER_VAL)
    {
        Serial.println(F("Counter overflow - re-enroll card"));
        return false;
    }

    byte newTag[32];
    computeExpectedTag(newCounter, newTag);

    counterDB[uidIndex] = newCounter;

    // Re-read card to write updated counter + tag
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(100);

    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial())
    {
        Serial.println(F("Card removed before update"));
        counterDB[uidIndex] = cardCounter;
        return false;
    }

    if (!writeCardData(newCounter, newTag))
    {
        Serial.println(F("Card write failed - rolling back"));
        counterDB[uidIndex] = cardCounter;
        return false;
    }

    Serial.print(F("Counter updated to: "));
    Serial.println(newCounter);

    return true;
}

// --------------------------------------------------
// Serial commands
// --------------------------------------------------

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
            Serial.println(F("UID added. Tap card and send ENROLL to initialize it."));
        else
            Serial.println(F("Storage full"));
    }

    else if (token != nullptr && strcmp(token, "ENROLL") == 0)
    {
        // Writes counter = 0 and its matching tag to whatever card is
        // currently on the reader, and resets the DB counter if that
        // UID is already on the whitelist.
        byte tag[32];
        computeExpectedTag(0, tag);

        if (writeCardData(0, tag))
        {
            Serial.println(F("Card enrolled (counter reset to 0)"));

            int idx = findUID();
            if (idx != -1)
                counterDB[idx] = 0;
        }
        else
        {
            Serial.println(F("Enroll write failed - hold card closer"));
        }
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


// --------------------------------------------------
// Magic card detection
// --------------------------------------------------

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



// --------------------------------------------------
// Wait for physical card removal
// --------------------------------------------------

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


// --------------------------------------------------
// Setup
// --------------------------------------------------

void setup()
{
    Serial.begin(9600);

    SPI.begin();

    rfid.PCD_SetAntennaGain(MFRC522::RxGain_max);
    rfid.PCD_Init();

    delay(4);

    for (byte i = 0; i < 6; i++)
        authKey.keyByte[i] = 0xFF;

    Serial.println(F("RFID HMAC+counter auth ready."));
    Serial.println(F("To enroll: <pswd> ADD <uid>, then tap card and send <pswd> ENROLL"));
}


// --------------------------------------------------
// Main loop
// --------------------------------------------------

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

    if (authenticateCombined(uidIndex))
    {
        Serial.println(F("TAG + COUNTER OK"));
        Serial.println(F("ACCESS GRANTED"));
    }
    else
    {
        Serial.println(F("TAG/COUNTER FAIL"));
        Serial.println(F("ACCESS DENIED"));
    }

    waitForCardRemoval();
}
