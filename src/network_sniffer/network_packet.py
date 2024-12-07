from datetime import datetime
import uuid

class NetworkPacket:
    """
    Classe représentant un paquet réseau avec des attributs nécessaires.
    """

    def __init__(self, data: bytes):
        """
        Initialise un paquet réseau avec un ID unique, des données, et un horodatage.

        Args:
        - data (bytes): Les données contenues dans le paquet.
        """
        self.id = self.generate_packet_id()
        self.timestamp = self.get_current_timestamp()
        self.data = data

    @staticmethod
    def generate_packet_id():
        """
        Génère un ID unique pour le paquet.

        Returns:
        - str: Un identifiant unique basé sur UUID4.
        """
        return str(uuid.uuid4())

    @staticmethod
    def get_current_timestamp():
        """
        Récupère l'horodatage actuel au format ISO 8601.

        Returns:
        - str: Horodatage sous forme de chaîne de caractères.
        """
        return datetime.now().isoformat()

    def __str__(self):
        """
        Représente l'objet sous forme de chaîne.

        Returns:
        - str: Représentation lisible du paquet.
        """
        return f"Packet(ID: {self.id}, Timestamp: {self.timestamp}, Data: {self.data})"

