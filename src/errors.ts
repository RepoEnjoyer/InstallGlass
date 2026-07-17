export class InstallGlassError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "InstallGlassError";
    this.code = code;
  }
}
