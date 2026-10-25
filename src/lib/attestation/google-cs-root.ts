/**
 * Pinned Google Cloud Confidential Space Root CA certificate and fingerprints.
 *
 * Official reference:
 * - PKI token validation endpoint: https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root
 * - Docs: https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources#request
 */

/**
 * Minimal Reflect metadata polyfill required by `@peculiar/x509@2.2.0` (`tsyringe`)
 * before `@peculiar/x509` is evaluated in browser or Node environments.
 *
 * Installed lazily by `getX509()` using non-enumerable `Object.defineProperty`
 * descriptors so importing attestation modules has zero global side effects and
 * `Object.keys(Reflect)` never changes.
 */
export function ensureReflectMetadata(): void {
  const r = Reflect as unknown as {
    getMetadata?: (metadataKey: unknown, target: object, propertyKey?: string | symbol) => unknown;
    getOwnMetadata?: (
      metadataKey: unknown,
      target: object,
      propertyKey?: string | symbol,
    ) => unknown;
    defineMetadata?: (
      metadataKey: unknown,
      metadataValue: unknown,
      target: object,
      propertyKey?: string | symbol,
    ) => void;
    metadata?: (
      metadataKey: unknown,
      metadataValue: unknown,
    ) => (target: object, propertyKey?: string | symbol) => void;
  };

  if (
    typeof r.getMetadata === "function" &&
    typeof r.getOwnMetadata === "function" &&
    typeof r.defineMetadata === "function" &&
    typeof r.metadata === "function"
  ) {
    return;
  }

  const store = new WeakMap<object, Map<string | symbol | undefined, Map<unknown, unknown>>>();

  const getMap = (
    target: unknown,
    propertyKey: string | symbol | undefined,
    create: boolean,
  ): Map<unknown, unknown> | undefined => {
    if ((typeof target !== "object" || target === null) && typeof target !== "function") {
      return undefined;
    }
    let targetMap = store.get(target as object);
    if (!targetMap) {
      if (!create) return undefined;
      targetMap = new Map();
      store.set(target as object, targetMap);
    }
    let propMap = targetMap.get(propertyKey);
    if (!propMap && create) {
      propMap = new Map();
      targetMap.set(propertyKey, propMap);
    }
    return propMap;
  };

  const defineMetadataFn = (
    metadataKey: unknown,
    metadataValue: unknown,
    target: object,
    propertyKey?: string | symbol,
  ): void => {
    const map = getMap(target, propertyKey, true);
    if (map) {
      map.set(metadataKey, metadataValue);
    }
  };

  const getOwnMetadataFn = (
    metadataKey: unknown,
    target: object,
    propertyKey?: string | symbol,
  ): unknown => {
    const map = getMap(target, propertyKey, false);
    return map ? map.get(metadataKey) : undefined;
  };

  const getMetadataFn = (
    metadataKey: unknown,
    target: object,
    propertyKey?: string | symbol,
  ): unknown => {
    let cur: unknown = target;
    while (cur && (typeof cur === "object" || typeof cur === "function")) {
      const own = (r.getOwnMetadata ?? getOwnMetadataFn)(metadataKey, cur as object, propertyKey);
      if (own !== undefined) return own;
      cur = Object.getPrototypeOf(cur);
    }
    return undefined;
  };

  const metadataFn =
    (metadataKey: unknown, metadataValue: unknown) =>
    (target: object, propertyKey?: string | symbol): void => {
      (r.defineMetadata ?? defineMetadataFn)(metadataKey, metadataValue, target, propertyKey);
    };

  if (typeof r.defineMetadata !== "function") {
    Object.defineProperty(Reflect, "defineMetadata", {
      value: defineMetadataFn,
      configurable: true,
      writable: true,
      enumerable: false,
    });
  }

  if (typeof r.getOwnMetadata !== "function") {
    Object.defineProperty(Reflect, "getOwnMetadata", {
      value: getOwnMetadataFn,
      configurable: true,
      writable: true,
      enumerable: false,
    });
  }

  if (typeof r.getMetadata !== "function") {
    Object.defineProperty(Reflect, "getMetadata", {
      value: getMetadataFn,
      configurable: true,
      writable: true,
      enumerable: false,
    });
  }

  if (typeof r.metadata !== "function") {
    Object.defineProperty(Reflect, "metadata", {
      value: metadataFn,
      configurable: true,
      writable: true,
      enumerable: false,
    });
  }
}

export const GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
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
uyT5CnJulxSC5CT1
-----END CERTIFICATE-----`;

/**
 * Uppercase hex SHA-256 fingerprint of the Google Confidential Space Root CA DER bytes.
 */
export const GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA256 =
  "148B293821BB0C6A317F413C8BA475814091CB22D49B9E3C94198DB8E8F86C39" as const;

/**
 * Uppercase hex SHA-1 fingerprint of the Google Confidential Space Root CA DER bytes.
 * Matches Google's published value: B9:51:20:74:2C:24:E3:AA:34:04:2E:1C:3B:A3:AA:D2:8B:21:23:21
 */
export const GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA1 =
  "B95120742C24E3AA34042E1C3BA3AAD28B212321" as const;
