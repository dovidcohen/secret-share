/**
 * Client-side logo pipeline: downscale to the header's display envelope and
 * re-encode as PNG before upload. Whatever the admin picked, the server only
 * ever receives a small raster — SVG (and its script-in-svg risk) never enters
 * the system.
 */

const MAX_W = 512; // covers retina at the header's 28px display height
const MAX_H = 128;
const MAX_ENCODED_BYTES = 100 * 1024;

export async function prepareLogo(file: File): Promise<Blob> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new Error("That file could not be read as an image.");
  }
  try {
    const scale = Math.min(1, MAX_W / bitmap.width, MAX_H / bitmap.height);
    const w = Math.max(1, Math.round(bitmap.width * scale));
    const h = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("Could not process the image.");
    ctx.drawImage(bitmap, 0, 0, w, h);
    const blob = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob(resolve, "image/png"),
    );
    if (!blob) throw new Error("Could not encode the logo.");
    if (blob.size > MAX_ENCODED_BYTES) {
      throw new Error("Logo is still too large after processing (max 100 KB) — try a simpler image.");
    }
    return blob;
  } finally {
    bitmap.close();
  }
}
