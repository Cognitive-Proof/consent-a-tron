// IndexedDB storage. Key pairs are stored as CryptoKey objects (structured
// clone), so the non-extractable private key is never serialized to bytes.

export interface Identity {
  id: string;
  label: string;
  did: string;
  publicKey: string; // base64, raw Ed25519
  keys: CryptoKeyPair;
  email?: string;
  certChainPem?: string;
  certIssuer?: string;
  createdAt: string;
}

export interface HistoryEntry {
  id?: number;
  at: string;
  origin: string;
  identityId: string;
  action: string;
  summary: string;
}

const DB = "consent-wallet";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore("identities", { keyPath: "id" });
      req.result.createObjectStore("history", { keyPath: "id", autoIncrement: true });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const req = fn(db.transaction(store, mode).objectStore(store));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export const identities = {
  all: () => tx<Identity[]>("identities", "readonly", (s) => s.getAll() as IDBRequest<Identity[]>),
  get: (id: string) => tx<Identity | undefined>("identities", "readonly", (s) => s.get(id)),
  put: (identity: Identity) => tx("identities", "readwrite", (s) => s.put(identity)),
  remove: (id: string) => tx("identities", "readwrite", (s) => s.delete(id)),
};

export const history = {
  all: async () => (await tx<HistoryEntry[]>("history", "readonly", (s) => s.getAll() as IDBRequest<HistoryEntry[]>)).reverse(),
  add: (entry: HistoryEntry) => tx("history", "readwrite", (s) => s.add(entry)),
};
