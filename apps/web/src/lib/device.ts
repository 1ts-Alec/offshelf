// Pairing this browser, and turning its stored identity into a signer.

import { Signer, device_pubkey, new_device_seed, pairing_client_mac, pairing_server_ok, random_bytes } from "../wasm/oshelf_web.js";
import { Api, pairRequest } from "./api";
import * as store from "./store";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Pairs with the Pi serving this page using a code from it or a paired device. */
export async function pair(code: string, name: string): Promise<store.Device> {
  await store.clearAll();
  const seed = new_device_seed();
  const pubkey = device_pubkey(seed);
  const nonce = hex(random_bytes(16));
  const v = await pairRequest({
    name,
    pubkey,
    client_nonce: nonce,
    mac: pairing_client_mac(code, pubkey, nonce),
  });
  if (!pairing_server_ok(code, v.server_pubkey, v.device_id, nonce, v.mac)) {
    throw new Error("The server couldn't prove it knows the code. Not pairing.");
  }
  const device: store.Device = {
    id: v.device_id,
    name,
    serverPub: v.server_pubkey,
    seed: await store.seal("device-seed", seed),
  };
  await store.saveDevice(device);
  return device;
}

export async function apiFor(device: store.Device): Promise<Api> {
  const seed = await store.unseal("device-seed", device.seed);
  return new Api(new Signer(seed, device.id, device.serverPub));
}
