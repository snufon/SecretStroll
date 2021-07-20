"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple

# Optional import
from serialization import jsonpickle
from credential import *
import pickle
from petrelic.native.pairing import G1 as G1N

# Type aliases
State = Any

class Server:
    """Server"""


    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        self.users = []

    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        ###############################################
        #appended empty string to the subscriptions so we generated a key of correct length
        secret_key, public_key = generate_key(subscriptions)
        #transforming keys into strings
        secret = pickle.dumps(secret_key)
        public = pickle.dumps(public_key)
        ###############################################
        return secret, public



    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        self.users.append(username)

        secret = pickle.loads(server_sk)
        public = pickle.loads(server_pk)

        #creating attribute map for the issuer attributes: subscriptions in this case
        #starting from index 1, since index 0 corresponds to the user secret key
        nb_possible_sub = int((len(public) - 3) / 2) - 1 #getting number of possible subscriptions from the public key
        issuer_attributes = {}

        for i, sub in enumerate(subscriptions):
            issuer_attributes[i + 1] = sub
        for i in range(len(subscriptions) + 1, nb_possible_sub + 1):
            issuer_attributes[i] = "" #if subcriptions i is not part of the requested subscriptions
                                              #we replace the attribute with an empty string, to ensure we have the 
                                              #right amount of attributes, since every operation requires the same number
                                              #attributes
        
        #decode issuance request sent by client                                        
        issuance_req = pickle.loads(issuance_request)

        #creates blind signature on the user attributes (the user's secret key) and issuer attributes (subscriptions)
        blind_signature_and_attr = sign_issue_request(secret, public, issuance_req, issuer_attributes)

        #encodes to bytes the blinf signature
        return pickle.dumps(blind_signature_and_attr)


    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
       
        ###############################################
        #decode public key and disclosure proof
        public = pickle.loads(server_pk)
        disclosure_proof = pickle.loads(signature)

        #let's check that the revealed attributes and the attributes signed by the disclosure match:
        signed_attributes = list(disclosure_proof[2].values())
        matching_attributes = set(signed_attributes) == set(revealed_attributes)
        
        ###############################################
        return verify_disclosure_proof(public, disclosure_proof, message) and matching_attributes


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        self.username = ''
        self.subscriptions = []
        self.secret_key = ''


    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        ###############################################
        self.username = username
        self.subscriptions = subscriptions
        self.secret_key = G1N.order().random()

        #user_attributes in this case is just the user's secret key that we randomly generate
        user_attributes = {0: jsonpickle.encode(self.secret_key)}

        public_key = pickle.loads(server_pk)
        issuance_request, request_state = create_issue_request(public_key,user_attributes)
        ###############################################
        return pickle.dumps(issuance_request), request_state


    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        ###############################################
        blind_sign_and_attr = pickle.loads(server_response)
        public = pickle.loads(server_pk)

        credentials = obtain_credential(public, blind_sign_and_attr, private_state)
        ###############################################
        return pickle.dumps(credentials)


    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        ###############################################
        public = pickle.loads(server_pk)
        creds, sign =  pickle.loads(credentials)

        #user secret key and also every subcription not in types are hidden attributes
        hidden_attributes = []
        for cred in creds:
            if cred not in types:
                hidden_attributes.append(cred)


        disclosure_proof = create_disclosure_proof(public, (creds, sign), hidden_attributes, message)
        ###############################################
        return pickle.dumps(disclosure_proof)
