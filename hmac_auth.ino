#include <MFRC522.h>
#include <SPI.h>
#include <string.h>

// SHA256 implementation - no extra library needed
// Based on public domain implementation by Brad Conte

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

// Card memory layout:
// Block 4 (sector 1, block 0): first 16 bytes of HMAC tag
// Block 5 (sector 1, block 1): last 16 bytes of HMAC tag
// (SHA256 = 32 bytes total, fits in 2 blocks)
#define HMAC_BLOCK_A 4
#define HMAC_BLOCK_B 5

MFRC522 rfid(SS_PIN, RST_PIN);

byte nuidPICC[UID_LEN];

byte UIDs[MAX_UIDS][UID_LEN] = {
    {0x00, 0x00, 0x00, 0x00}
};

unsigned uidCount = 1;

char admin_password[MAX_PSWD_LEN] = "admin";

char serialBuf[MAX_BUFFER_SIZE];
byte serialLen = 0;

MFRC522::MIFARE_Key authKey;


// --------------------------------------------------
// SHA256 implementation (public domain)
// --------------------------------------------------

#define SHA256_BLOCK_SIZE 32

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

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++)
    {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
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
        hash[i]      = (ctx->state[0] >> (24 - i*8)) & 0xFF;
        hash[i+4]    = (ctx->state[1] >> (24 - i*8)) & 0xFF;
        hash[i+8]    = (ctx->state[2] >> (24 - i*8)) & 0xFF;
        hash[i+12]   = (ctx->state[3] >> (24 - i*8)) & 0xFF;
        hash[i+16]   = (ctx->state[4] >> (24 - i*8)) & 0xFF;
        hash[i+20]   = (ctx->state[5] >> (24 - i*8)) & 0xFF;
        hash[i+24]   = (ctx->state[6] >> (24 - i*8)) & 0xFF;
        hash[i+28]   = (ctx->state[7] >> (24 - i*8)) & 0xFF;
    }
}


// --------------------------------------------------
// HMAC-SHA256
// Input:  key, keyLen, message, msgLen
// Output: 32-byte hash in outHash
// --------------------------------------------------

void hmacSHA256(
    const byte *key,    byte keyLen,
    const byte *msg,    byte msgLen,
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

    // Inner hash: SHA256(ipad || message)
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, msg, msgLen);
    sha256_final(&ctx, innerHash);

    // Outer hash: SHA256(opad || innerHash)
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, innerHash, 32);
    sha256_final(&ctx, outHash);
}


// --------------------------------------------------
// Compute expected HMAC tag for current card UID
// --------------------------------------------------

void computeExpectedHMAC(byte *outHash)
{
    hmacSHA256(
        (const byte *)HMAC_KEY,
        HMAC_KEY_LEN,
        nuidPICC,
        UID_LEN,
        outHash
    );
}


// --------------------------------------------------
// Read HMAC tag from card memory (blocks 4 and 5)
// --------------------------------------------------

bool readHMACFromCard(byte *outHash)
{
    // Read first 16 bytes from block 4
    MFRC522::StatusCode status = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        HMAC_BLOCK_A,
        &authKey,
        &rfid.uid
    );

    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("HMAC auth block A failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }

    byte buf[18];
    byte bufSize = sizeof(buf);

    status = rfid.MIFARE_Read(HMAC_BLOCK_A, buf, &bufSize);

    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("HMAC read block A failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }

    memcpy(outHash, buf, 16);

    // Read last 16 bytes from block 5
    status = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        HMAC_BLOCK_B,
        &authKey,
        &rfid.uid
    );

    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("HMAC auth block B failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }

    bufSize = sizeof(buf);

    status = rfid.MIFARE_Read(HMAC_BLOCK_B, buf, &bufSize);

    if (status != MFRC522::STATUS_OK)
    {
        Serial.println(F("HMAC read block B failed"));
        rfid.PCD_StopCrypto1();
        return false;
    }

    memcpy(outHash + 16, buf, 16);

    rfid.PCD_StopCrypto1();
    return true;
}


// --------------------------------------------------
// Write HMAC tag to card memory (enrollment)
// --------------------------------------------------

bool writeHMACToCard(const byte *hash)
{
    // Write first 16 bytes to block 4
    MFRC522::StatusCode status = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        HMAC_BLOCK_A,
        &authKey,
        &rfid.uid
    );

    if (status != MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();
        return false;
    }

    byte buf[16];
    memcpy(buf, hash, 16);

    status = rfid.MIFARE_Write(HMAC_BLOCK_A, buf, 16);

    if (status != MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();
        return false;
    }

    // Write last 16 bytes to block 5
    status = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        HMAC_BLOCK_B,
        &authKey,
        &rfid.uid
    );

    if (status != MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();
        return false;
    }

    memcpy(buf, hash + 16, 16);

    status = rfid.MIFARE_Write(HMAC_BLOCK_B, buf, 16);

    rfid.PCD_StopCrypto1();

    return status == MFRC522::STATUS_OK;
}


// --------------------------------------------------
// HMAC authentication
// Reads tag from card, computes expected, compares
// --------------------------------------------------

bool authenticateHMAC()
{
    byte cardHash[32];
    byte expectedHash[32];

    if (!readHMACFromCard(cardHash))
    {
        Serial.println(F("Could not read HMAC from card"));
        return false;
    }

    computeExpectedHMAC(expectedHash);

    // Constant-time comparison to prevent timing attacks
    byte diff = 0;
    for (byte i = 0; i < 32; i++)
        diff |= (cardHash[i] ^ expectedHash[i]);

    return diff == 0;
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
        memcpy(UIDs[i], UIDs[i + 1], UID_LEN);

    uidCount--;

    memset(UIDs[uidCount], 0, UID_LEN);

    return true;
}


// --------------------------------------------------
// UID comparison
// --------------------------------------------------

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


bool findUID()
{
    for (size_t i = 0; i < uidCount; i++)
    {
        if (compareUID(i))
            return true;
    }
    return false;
}


// --------------------------------------------------
// Serial commands
// (ADD supports enrollment: ADD <uid> writes HMAC to card)
// --------------------------------------------------

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
        {
            Serial.println(F("UID added"));
            Serial.println(F("Hold card to reader to write HMAC"));
        }
        else
        {
            Serial.println(F("Storage full"));
        }
    }

    else if (token != nullptr && strcmp(token, "ENROLL") == 0)
    {
        // ENROLL: compute and write HMAC to currently present card
        byte hash[32];
        computeExpectedHMAC(hash);

        if (writeHMACToCard(hash))
            Serial.println(F("HMAC written to card"));
        else
            Serial.println(F("HMAC write failed - hold card closer"));
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
// Gen1A detection
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


// --------------------------------------------------
// Gen2 / CUID detection
// --------------------------------------------------

bool isGen2Magic()
{
    MFRC522::MIFARE_Key key;

    for (byte i = 0; i < 6; i++)
        key.keyByte[i] = 0xFF;

    MFRC522::PICC_Type piccType =
        rfid.PICC_GetType(rfid.uid.sak);

    if (piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
        piccType != MFRC522::PICC_TYPE_MIFARE_4K)
    {
        return false;
    }

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

    byte block0[18];
    byte bufferSize = sizeof(block0);

    status = rfid.MIFARE_Read(0, block0, &bufferSize);

    if (status != MFRC522::STATUS_OK)
    {
        rfid.PCD_StopCrypto1();
        return false;
    }

    // Write garbage - if accepted it is a magic card
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
        rfid.MIFARE_Write(0, block0, 16);
        Serial.println(F("Block 0 restored"));
    }

    rfid.PCD_StopCrypto1();

    return magic;
}


// --------------------------------------------------
// UID reading
// --------------------------------------------------

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


// --------------------------------------------------
// Serial input
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

    Serial.println(F("RFID HMAC auth ready."));
    Serial.println(F("To enroll card: ADD <uid> then ENROLL"));
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

    // --- Magic card detection ---

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

    // --- UID whitelist check ---

    if (!findUID())
    {
        Serial.println(F("UID NOT RECOGNIZED"));
        Serial.println(F("ACCESS DENIED"));
        waitForCardRemoval();
        return;
    }

    Serial.println(F("UID RECOGNIZED"));

    // --- Re-read card for HMAC authentication ---

    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(150);

    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial())
    {
        Serial.println(F("Card removed too early"));
        return;
    }

    // --- HMAC check ---

    if (authenticateHMAC())
    {
        Serial.println(F("HMAC OK"));
        Serial.println(F("ACCESS GRANTED"));
    }
    else
    {
        Serial.println(F("HMAC FAIL"));
        Serial.println(F("ACCESS DENIED"));
    }

    waitForCardRemoval();
}
