/**
 * Optical (QR) transfer wire constants — changing any of these is a breaking
 * protocol version bump (a sender and receiver on different values cannot
 * interoperate).
 */
export const OPTICAL_MAGIC = 0x53; // 'S'
export const OPTICAL_VERSION = 0x01;
export const HEADER_BYTES = 20;
export const MAX_K = 0xffff;

/** Frame-header flag: the container is encrypted (UI hint before reassembly). */
export const FRAME_FLAG_ENCRYPTED = 0b0000_0001;

export interface OpticalProfile {
  id: "compat" | "default" | "dense";
  label: string;
  qrVersion: number;
  /** Total QR byte capacity at EC level L (measured against qrcode@1.5). */
  frameBytes: number;
  /** frameBytes − HEADER_BYTES: fountain payload per frame. */
  blockSize: number;
}

export const PROFILES: Record<OpticalProfile["id"], OpticalProfile> = {
  compat: { id: "compat", label: "Compatible · V12", qrVersion: 12, frameBytes: 367, blockSize: 347 },
  default: { id: "default", label: "Balanced · V17", qrVersion: 17, frameBytes: 644, blockSize: 624 },
  dense: { id: "dense", label: "Dense · V22", qrVersion: 22, frameBytes: 1003, blockSize: 983 },
};

export const DEFAULT_PROFILE: OpticalProfile = PROFILES.default;
