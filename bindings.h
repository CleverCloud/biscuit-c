#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Biscuit Biscuit;

typedef struct BiscuitBuilder BiscuitBuilder;

typedef struct KeyPair KeyPair;

typedef struct PublicKey PublicKey;

typedef struct Verifier Verifier;

typedef struct {
  const uint8_t *ptr;
  uintptr_t len;
} Slice;

typedef struct {
  uint8_t *ptr;
  uintptr_t len;
  uintptr_t capacity;
} Bytes;

const char *error_message(void);

KeyPair *keypair_new(Slice seed);

PublicKey *keypair_public(const KeyPair *kp);

void keypair_free(KeyPair *_kp);

void public_key_free(PublicKey *_kp);

BiscuitBuilder *biscuit_builder(const KeyPair *keypair);

bool biscuit_builder_add_authority_fact(BiscuitBuilder *builder, const char *fact);

bool biscuit_builder_add_authority_rule(BiscuitBuilder *builder, const char *rule);

bool biscuit_builder_add_authority_caveat(BiscuitBuilder *builder, const char *caveat);

Biscuit *biscuit_builder_build(BiscuitBuilder *builder, Slice seed);

void biscuit_builder_free(BiscuitBuilder *_builder);

Biscuit *biscuit_from(Slice biscuit);

Biscuit *biscuit_from_sealed(Slice biscuit, Slice secret);

Bytes biscuit_serialize(const Biscuit *biscuit);

Bytes biscuit_serialize_sealed(const Biscuit *biscuit, Slice secret);

Verifier *biscuit_verify(const Biscuit *biscuit, const PublicKey *root);

void biscuit_free(Biscuit *_biscuit);

void verifier_free(Verifier *_verifier);

void bytes_free(Bytes bytes);
