import { timingSafeEqual } from "std/crypto/timing_safe_equal.ts";

export interface Payload {
  timestamp: string;
  version: number;
  type: string;
  tailnet: string;
  message: string;
  data: Node | NodeExpiration | PolicyUpdate | UserRole | null;
}

export interface Node {
  nodeID: string;
  deviceName: string;
  managedBy: string;
  actor: string;
  url: string;
}

export interface NodeExpiration extends Node {
  expiration: string;
}

export interface PolicyUpdate {
  newPolicy: string;
  oldPolicy: string;
  url: string;
  actor: string;
}

export interface UserRole {
  user: string;
  url: string;
  actor: string;
  oldRoles: string[];
  newRoles: string[];
}

export const splitHeader = (header: string): Record<string, string> => {
  const result: Record<string, string> = {};
  header.split(",").forEach((str) => {
    if (!str.includes("=")) {
      return;
    }

    const [k, v] = str.split("=");
    result[k] = v;
  });
  return result;
};

export const validateSignature = async (
  toSign: string,
  serverSigV1: string,
  secretKey: string,
): Promise<boolean> => {
  const encoder = new TextEncoder();
  const messageBytes = encoder.encode(toSign);
  const secretBytes = encoder.encode(secretKey);

  const key = await crypto.subtle.importKey(
    "raw", // raw key for hmac secret
    secretBytes,
    {
      name: "HMAC",
      hash: { name: "SHA-256" },
    },
    false, // is the key extractable?
    ["sign", "verify"], // uses of the key
  );

  const sig = await crypto.subtle.sign("HMAC", key, messageBytes);

  const serverSig = hexDecode(serverSigV1);

  if (!crypto.subtle.verify("HMAC", key, serverSig, messageBytes)) {
    return false;
  }

  return timingSafeEqual(sig, serverSig);
};

export const hexDecode = (inp: string): ArrayBuffer => {
  const bytes: number[] = [];
  inp.replace(/../g, (pair) => {
    bytes.push(parseInt(pair, 16));
    return "";
  });
  return new Uint8Array(bytes).buffer;
};

export const validate = async (
  req: Request,
  secretKey: string,
): Promise<{ ok: boolean; body: string }> => {
  if (!req.headers.has("Tailscale-Webhook-Signature")) {
    return { ok: false, body: await req.text() };
  }

  const body = await req.text();

  const { t, v1 } = splitHeader(
    req.headers.get("Tailscale-Webhook-Signature") as string,
  );

  const then = new Date(0);
  then.setUTCSeconds(parseInt(t, 10));
  const now = new Date();
  const FIVE_MIN = 5 * 60 * 1000; // 5 minutes in milliseconds
  if ((now.getTime() - then.getTime()) > FIVE_MIN) {
    return { ok: false, body };
  }

  const stringToSign = `${t}.${body}`;
  return { ok: await validateSignature(stringToSign, v1, secretKey), body };
};
