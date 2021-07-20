from typing import Any, List, Tuple

from serialization import jsonpickle

from petrelic.bn import Bn
from petrelic.additive.pairing import (
    G1Element as G1EA,
    G2Element as G2EA,
    GTElement as GtEA,
    G1 as G1A,
    G2 as G2A,
    GT as GTA,
)
from petrelic.multiplicative.pairing import (
    G1Element as G1EM,
    G2Element as G2EM,
    GTElement as GtEM,
    G1 as G1M,
    G2 as G2M,
    GT as GTM,
)
from petrelic.native.pairing import (
    G1Element as G1EN,
    G2Element as G2EN,
    GTElement as GtEN,
    G1 as G1N,
    G2 as G2N,
    GT as GTN,
)

from credential import *
from stroll import *
# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = List[bytes]
PublicKey = List[bytes]
Signature = List[bytes]
Attribute = Any

#Testing basic blocks of the ABC

def test_sign_and_verify1():
    
    attributes = ["18","username"]
    secret,public = generate_key(attributes)
    signature = sign(secret,attributes)
    assert verify(public,signature,attributes)

def test_sign_and_verify2():
    
    attributes = ["15","username1","nationality","subscription","height"]
    secret,public = generate_key(attributes)
    signature = sign(secret,attributes)
    assert verify(public,signature,attributes)

def test_sign_and_verify3():
    
    attributes = ["15","username1","nationality","subscription","height"]
    secret,public = generate_key(attributes)
    signature = sign(secret,attributes)
    wrong_attributes = ["18","username1","nationality","subscription","height"]
    assert not verify(public,signature,wrong_attributes)

def test_issue_request():
    attributes = ["15","username1","nationality","subscription","height"]
    secret,public = generate_key(attributes)
    user_att = {0:"15",2:"nationality"}
    issuer_att = {1:"username1", 3:"subscription", 4:"height"}
    issue_req, state = create_issue_request(public, user_att)
    blind_sig = sign_issue_request(secret, public, issue_req,issuer_att)
    cred, sig = obtain_credential(public, blind_sig,state)
    assert verify(public,sig,cred)

def test_proof():
    attributes = ["15","username1","nationality","subscription","height"]
    secret,public = generate_key(attributes)
    user_att = {0:"15",2:"nationality"}
    issuer_att = {1:"username1", 3:"subscription", 4:"height"}
    issue_req, state = create_issue_request(public, user_att)
    proof = issue_req[1]
    C =  issue_req[0]
    assert verify_non_interactive_proof(proof,public,C)
    
def test_showing_prot():
    attributes = ["15","username1","nationality","subscription","height"]
    secret,public = generate_key(attributes)
    user_att = {0:"15",2:"nationality"}
    issuer_att = {1:"username1", 3:"subscription", 4:"height"}
    issue_req, state = create_issue_request(public, user_att)
    blind_sig = sign_issue_request(secret, public, issue_req,issuer_att)
    creds = obtain_credential(public, blind_sig,state)

    disc_proof = create_disclosure_proof(public,creds,["subscription", "height"],"".encode())    
    verif = verify_disclosure_proof(public, disc_proof, "".encode())
    assert verif

def test_showing_prot2():
    attributes = ["15","username1","nationality","subscription","height"]
    secret,public = generate_key(attributes)
    user_att = {0:"15",2:"nationality"}
    issuer_att = {1:"username1", 3:"subscription", 4:"height"}
    issue_req, state = create_issue_request(public, user_att)
    blind_sig = sign_issue_request(secret, public, issue_req,issuer_att)
    creds = obtain_credential(public, blind_sig,state)

    disc_proof = create_disclosure_proof(public,creds,["nationality"],"".encode())    
    verif = verify_disclosure_proof(public, disc_proof, "".encode())
    assert verif

#testing scroll.py scenarios
def test_secret_scroll_correct1():
    server = Server()
    client = Client()

    possible_subscriptions = ["restaurant","bar","dojo","gym"]

    secret,public = server.generate_ca(possible_subscriptions + ["username"])

    username, subscriptions = "Bob", ["bar","gym"]

    issuance_request, state = client.prepare_registration(public, username,subscriptions)

    signed_issue_request = server.process_registration(secret, public, issuance_request,username, subscriptions)

    credentials = client.process_registration_response(public, signed_issue_request, state)

    lat,lon = 46.52345, 6.57890

    disc_proof_request = client.sign_request(public, credentials, (f"{lat},{lon}").encode("utf-8"), ["bar","gym"]) 

    assert server.check_request_signature(public, (f"{lat},{lon}").encode("utf-8"), ["bar", "gym"], disc_proof_request)

def test_secret_scroll_not_correct1():
    server = Server()
    client = Client()

    possible_subscriptions = ["restaurant","bar","dojo","gym"]

    secret,public = server.generate_ca(possible_subscriptions + ["username"])

    username, subscriptions = "Bob", ["bar","gym"]

    issuance_request, state = client.prepare_registration(public, username,subscriptions)

    signed_issue_request = server.process_registration(secret, public, issuance_request,username, subscriptions)

    credentials = client.process_registration_response(public, signed_issue_request, state)

    lat,lon = 46.52345, 6.57890

    #asking for a type of service for which Bob has no credentials for

    disc_proof_request = client.sign_request(public, credentials, (f"{lat},{lon}").encode("utf-8"), ["bar","dojo"]) 

    assert not server.check_request_signature(public, (f"{lat},{lon}").encode("utf-8"), ["bar", "dojo"], disc_proof_request)


def test_secret_scroll_not_correct2():
    server = Server()
    client = Client()

    possible_subscriptions = ["restaurant","bar","dojo","gym"]

    secret,public = server.generate_ca(possible_subscriptions + ["username"])

    username, subscriptions = "Bob", ["bar","gym"]

    issuance_request, state = client.prepare_registration(public, username,subscriptions)

    signed_issue_request = server.process_registration(secret, public, issuance_request,username, subscriptions)

    credentials = client.process_registration_response(public, signed_issue_request, state)

    lat,lon = 46.52345, 6.57890

    #asking for a type of service for which is not part of the possible subscriptions

    disc_proof_request = client.sign_request(public, credentials, (f"{lat},{lon}").encode("utf-8"), ["night_club"]) 

    assert not server.check_request_signature(public, (f"{lat},{lon}").encode("utf-8"), ["night_club"], disc_proof_request)
