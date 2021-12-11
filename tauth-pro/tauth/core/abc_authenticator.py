from abc import ABC, abstractmethod


class Authenticator(ABC):
    """
    Abstract class used for decoupling the usage of instantiable Authenticators
    such as KeycloakAuthenticator from other implementation classes (API authentications...).
    """
    @abstractmethod
    def connect(self) -> object:
        pass

    @abstractmethod
    def validate_credentials(self, **credentials) -> dict:
        pass

    @abstractmethod
    def create_user(self, **kwargs):
        pass

    @abstractmethod
    def update_user(self, user_id, **kwargs):
        pass

    @abstractmethod
    def delete_user(self, user_id):
        pass

    @abstractmethod
    def logout(self, token):
        pass

