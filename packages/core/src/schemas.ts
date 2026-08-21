export const inspectDocumentSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://www.aep.foundation/schemas/inspect-document.schema.json",
  title: "AEP Inspect Document",
  type: "object",
  required: ["aep_version", "bindings", "commands", "core", "http", "identity", "service"],
  additionalProperties: true,
  properties: {
    aep_version: {
      type: "string",
      pattern: "^[0-9]+\\.[0-9]+$"
    },
    bindings: {
      type: "object",
      required: ["supported"],
      additionalProperties: true,
      properties: {
        supported: {
          type: "array",
          minItems: 1,
          items: {
            type: "string",
            enum: ["http"]
          }
        }
      }
    },
    claims: {
      type: "object",
      additionalProperties: true,
      properties: {
        required: {
          type: "array",
          items: {
            type: "string"
          }
        },
        preferred: {
          type: "array",
          items: {
            type: "string"
          }
        },
        optional: {
          type: "array",
          items: {
            type: "string"
          }
        }
      }
    },
    commands: {
      type: "object",
      required: ["supported"],
      additionalProperties: true,
      properties: {
        supported: {
          type: "array",
          minItems: 1,
          items: {
            type: "string",
            enum: ["inspect", "enroll", "grant", "revoke", "status"]
          }
        },
        grant_types: {
          type: "array",
          items: {
            type: "string"
          }
        }
      }
    },
    core: {
      type: "object",
      additionalProperties: true,
      properties: {
        signing_algorithms: {
          type: "array",
          minItems: 1,
          items: {
            type: "string"
          }
        }
      }
    },
    extensions: {
      type: "object",
      additionalProperties: true,
      properties: {
        supported: {
          type: "array",
          items: {
            type: "string"
          }
        }
      }
    },
    http: {
      type: "object",
      required: ["endpoint_base"],
      additionalProperties: true,
      properties: {
        endpoint_base: {
          type: "string",
          pattern: "^/"
        }
      }
    },
    identity: {
      type: "object",
      required: ["methods"],
      additionalProperties: true,
      properties: {
        methods: {
          type: "array",
          minItems: 1,
          items: {
            type: "string",
            pattern: "^[a-z0-9]+(?::[a-z0-9]+)*(?:-[a-z0-9]+)*$"
          }
        }
      }
    },
    service: {
      type: "object",
      required: ["did"],
      additionalProperties: true,
      properties: {
        did: {
          type: "string",
          pattern: "^did:"
        }
      }
    }
  }
} as const;

export const claimValuesSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://www.aep.foundation/schemas/claim-values.schema.json",
  title: "Claim Values",
  description:
    "Person and contact claim values. Unknown claim names are permitted for forward compatibility.",
  type: "object",
  additionalProperties: true,
  properties: {
    "contact.address.primary": {
      type: "object",
      required: ["country", "first_name", "last_name", "line1"],
      additionalProperties: true,
      properties: {
        city: {
          type: "string",
          minLength: 1
        },
        country: {
          type: "string",
          pattern: "^[A-Z]{2}$"
        },
        first_name: {
          type: "string",
          minLength: 1
        },
        last_name: {
          type: "string",
          minLength: 1
        },
        line1: {
          type: "string",
          minLength: 1
        },
        line2: {
          type: "string"
        },
        line3: {
          type: "string"
        },
        postcode: {
          type: "string"
        },
        postal_code: false,
        region: {
          type: "string"
        }
      }
    },
    "contact.email": {
      type: "string",
      minLength: 3,
      format: "email"
    },
    "contact.mobile": {
      type: "string",
      pattern: "^\\+[1-9][0-9]{1,14}$"
    },
    "person.birthdate": {
      type: "string",
      format: "date"
    },
    "person.first_name": {
      type: "string",
      minLength: 1
    },
    "person.last_name": {
      type: "string",
      minLength: 1
    },
    "person.username": {
      type: "string",
      minLength: 1
    }
  }
} as const;
