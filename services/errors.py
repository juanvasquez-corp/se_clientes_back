class ServiceError(Exception):
    """Error de negocio cuyo mensaje puede exponerse al cliente."""

    status_code = 400


class AuthenticationError(ServiceError):
    status_code = 401

    def __init__(self, message: str = "Sesión inválida o finalizada"):
        super().__init__(message)


class PermissionDenied(ServiceError):
    status_code = 403

    def __init__(self, message: str = "Acceso denegado"):
        super().__init__(message)


class NotFound(ServiceError):
    status_code = 404

    def __init__(self):
        super().__init__("Usuario no encontrado")


class Conflict(ServiceError):
    status_code = 409


class RateLimited(ServiceError):
    status_code = 429

    def __init__(self):
        super().__init__("Demasiados intentos. Intenta más tarde")


class StorageUnavailable(ServiceError):
    status_code = 503

    def __init__(self):
        super().__init__("Servicio temporalmente no disponible")
