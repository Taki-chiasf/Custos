// Custos runtime exceptions. Mirror `custos.exceptions` (Python).

export class PermissionDenied extends Error {
  constructor(message = "permission denied") {
    super(message);
    this.name = "PermissionDenied";
  }
}

export class PolicyValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyValidationError";
  }
}