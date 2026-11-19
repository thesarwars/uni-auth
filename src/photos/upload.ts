/** A file field of a multipart form, as app.factory.ts's onFile leaves it in the body. */
export interface Upload {
  data: Buffer;
  /** Larger than the limit: data holds only its first bytes. */
  tooLarge: boolean;
}

export const isUpload = (v: unknown): v is Upload =>
  typeof v === 'object' && v !== null && Buffer.isBuffer((v as Upload).data);
