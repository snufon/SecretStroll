"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple

from serialization import jsonpickle
import hashlib

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


# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = List[bytes]
PublicKey = List[bytes]
Signature = Tuple[bytes]
Attribute = bytes
AttributeMap = dict
IssueRequest = Tuple[bytes,Any]
BlindSignature = Signature, AttributeMap
RequestState = bytes, AttributeMap
AnonymousCredential = List[Attribute], Signature
DisclosureProof = Any


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    secret_key = []
    public_key = []

    #picking x, y1, ..., yn at random in Zp
    x = G1N.order().random()
    y = []

    for i in range(len(attributes)):
        y.append(G1N.order().random())

    #pick generators from G1 and G2
    g1 = G1M.generator()
    g2 = G2M.generator()

    X1 = g1.pow(x)
    X2 = g2.pow(x)

    public_key.append(g1)
    public_key.extend(list(map(lambda y: g1 ** y,y)))
    public_key.append(g2)
    public_key.append(X2)
    public_key.extend(list(map(lambda y: g2 ** y,y)))

    secret_key.append(x)
    secret_key.append(X1)
    secret_key.extend(y)

    #serialization to bytes both keys
    public_key = list(map(lambda p: jsonpickle.encode(p),public_key))
    secret_key = list(map(lambda s: jsonpickle.encode(s),secret_key))
    return secret_key, public_key




def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:

    #sampling h from G1
    h = G1M.generator()

    #creating the exposant part of the signature
    sum = jsonpickle.decode(sk[0]) 
    for i, y in enumerate(sk[2:len(sk)]): 
        sum = sum + (jsonpickle.decode(y) * Bn.from_binary(msgs[i].encode()))

    return jsonpickle.encode(h), jsonpickle.encode(h ** sum)


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """

    #recreatign exposant part of the signature
    product = jsonpickle.decode(pk[len(msgs) + 3 - 1])
    for i, y  in enumerate(pk[len(msgs) + 4 - 1: 2*len(msgs) + 4 -1]):
        product = product * (jsonpickle.decode(y) ** Bn.from_binary(msgs[i].encode()))

    #checking that the signaure is correct using the bilinear function and that sigma1 is not the neutral element
    if (jsonpickle.decode(signature[0]).pair(product) == jsonpickle.decode(signature[1]).pair(jsonpickle.decode(pk[len(msgs) + 2 -1])) 
                    and not jsonpickle.decode(signature[0]).is_neutral_element()):
        return True
    else :
        return False



#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##
def zero_knowledge_proof(t, user_attributes, C, pk):
    """Creates the zero knowledge proof for the user_attributes,given commitment C"""
    #sampling all rm anc rt from Zp
    rm = {}
    for i in user_attributes:
        rm[i] = G1N.order().random()

    rt = G1N.order().random()

    R = jsonpickle.decode(pk[0]).pow(rt)
    for i in user_attributes:
        R = R * (jsonpickle.decode(pk[i + 1]).pow(rm[i]))

    #computing challenge from all public info: public key, commitment and R 
    #doing SHA256 hash of the concat binary of the public info
    challenge = C.to_binary() + R.to_binary()
    for i in range(0,len(pk)):
        challenge = challenge + jsonpickle.decode(pk[i]).to_binary()
    challenge = hashlib.sha256(challenge).digest()
    #convert to Bn
    challenge = Bn.from_binary(challenge)

    #creating dictionnary of sms for each attribute
    sm = {}
    for i in rm:
        sm[i] = (rm[i] - challenge * Bn.from_binary(user_attributes[i].encode())).mod(G1M.order())
        sm[i] = jsonpickle.encode(sm[i])
    st = (rt - challenge * t).mod(G1M.order())
    st = jsonpickle.encode(st)

    #every Bn and G1 Elem is encoded in bytes
    return jsonpickle.encode(R), sm, st

def verify_non_interactive_proof(proof,pk, C):
    """Verifies that the zeros knowledge proof for user attributes is correct, given the commitment C and R, st and all sm"""
    R = jsonpickle.decode(proof[0])
    sm = proof[1]
    st = jsonpickle.decode(proof[2])

    #computing challenge from all public info: public key, commitment and R 
    #doing SHA256 hash of the concat binary of the public info
    challenge = jsonpickle.decode(C).to_binary() + R.to_binary()
    for i in range(0,len(pk)):
        challenge = challenge + jsonpickle.decode(pk[i]).to_binary()
    challenge = hashlib.sha256(challenge).digest()
    #convert to Bn
    challenge = Bn.from_binary(challenge)

    verif = jsonpickle.decode(C).pow(challenge)
    for i in sm:
        verif = verif * (jsonpickle.decode(pk[i + 1]).pow(jsonpickle.decode(sm[i])))
    verif = verif * jsonpickle.decode(pk[0]).pow(st)

    #checking if verif == R
    return R == verif



def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> (IssueRequest, RequestState):
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    #random t in Zp
    t = G1N.order().random()

    #computes commitment
    C = jsonpickle.decode(pk[0]).pow(t)
    for i in user_attributes:
        C = C * (jsonpickle.decode(pk[i + 1]).pow(Bn.from_binary(user_attributes[i].encode())))

    #get non-intercative proof for C
    proof = zero_knowledge_proof(t, user_attributes, C, pk)

    #also return the "state" of the request : the sampled t and user attributes
    #only the commitment and proof will be sent to the server, the state of the request will be stored by the client
    return (jsonpickle.encode(C), proof), (jsonpickle.encode(t),user_attributes)


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    #check commitment and zk proof are correct
    C = request[0]
    proof = request[1]

    assert verify_non_interactive_proof(proof,pk,C)

    #random u in Zp
    u = G1N.order().random()

    #creates a signature on both user attributes and issuer attributes
    product = jsonpickle.decode(C)*jsonpickle.decode(sk[1])
    for i in issuer_attributes:
        product = product * (jsonpickle.decode(pk[i + 1]).pow(Bn.from_binary(issuer_attributes[i].encode())))

    signature = jsonpickle.encode(jsonpickle.decode(pk[0]).pow(u)), jsonpickle.encode(product.pow(u))

    #sends both the signature and the issuer attributes (in our case the subscriptions) to the user
    return signature, issuer_attributes


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        state: RequestState
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """

    signature1, signature2 = jsonpickle.decode(response[0][0]), jsonpickle.decode(response[0][1])

    t = jsonpickle.decode(state[0])

    #compute final siganture with the t sampled during the issue request
    final_signature = (jsonpickle.encode(signature1)
                        ,jsonpickle.encode(signature2/(signature1.pow(t))))

    # getting the ordered list of credentials from issuer and user attributes
    issuer_attributes = response[1]
    user_attributes = state[1]

    credentials_dic = dict(issuer_attributes)
    credentials_dic.update(user_attributes)

    #putting them in the right order (order is very important, since part of the signature on the credentials is based on it)
    credentials = []
    for i in sorted (credentials_dic.keys()):
        credentials.append(credentials_dic[i])

    #checking if signature is valid for these credentials
    assert verify(pk, final_signature, credentials)

    return credentials, final_signature





## SHOWING PROTOCOL ##


def zero_knowledge_proof_showing_protocol(t, hidden_attributes, right_side_commit, pk, random_signature, message):
    """
    Creates zero knowledge proof for showing protocol, given the commitment, random signature and message to sign using the proof
    """
    #sampling all rm anc rt from Zp
    nb_attr = int((len(pk) - 3) / 2)

    rm = {}
    for i in hidden_attributes:
        rm[i] = G1N.order().random()

    rt = G1N.order().random()

    R = (random_signature[0].pair(jsonpickle.decode(pk[1 + nb_attr]))).pow(rt)
    for i in hidden_attributes:
        R = R * ((random_signature[0].pair(jsonpickle.decode(pk[3 + nb_attr + i]))).pow(rm[i]))

    #computing challenge from all public info: public key, commitment and R, as well as the message to sign
    #doing SHA256 hash of the concat binary of the public info
    challenge = right_side_commit.to_binary() + R.to_binary() + message
    for i in range(0,len(pk)):
        challenge = challenge + jsonpickle.decode(pk[i]).to_binary()
    challenge = hashlib.sha256(challenge).digest()
    #convert to Bn
    challenge = Bn.from_binary(challenge)


    #create dictionnary of sm
    sm = {}
    for i in rm:
        sm[i] = (rm[i] - challenge * Bn.from_binary(hidden_attributes[i].encode())).mod(G1M.order())
        sm[i] = jsonpickle.encode(sm[i])
    st = (rt - challenge * t).mod(G1M.order())
    st = jsonpickle.encode(st)

    return jsonpickle.encode(R), sm, st

def verify_non_interactive_proof_showing_protocol(proof,pk,right_side_commit,disclosed_attributes, random_signature, message):
    """Verifies the zero-knowledge proof for the showing protocol and if the message is signed correctly"""
    nb_attr = int((len(pk) - 3) / 2)

    R = jsonpickle.decode(proof[0])
    sm = proof[1]
    st = jsonpickle.decode(proof[2])
    random_signature = (jsonpickle.decode(random_signature[0]),jsonpickle.decode(random_signature[1]))
    right_side_commit = jsonpickle.decode(right_side_commit)

    #computing challenge from all public info: public key, commitment and R, as well as message m
    #doing SHA256 hash of the concat binary of the public info
    challenge = right_side_commit.to_binary() + R.to_binary() + message
    for i in range(0,len(pk)):
        challenge = challenge + jsonpickle.decode(pk[i]).to_binary()
    challenge = hashlib.sha256(challenge).digest()
    #convert challenge to Bn
    challenge = Bn.from_binary(challenge)

    verif = right_side_commit.pow(challenge)
    for i in sm:
        verif = verif * ((random_signature[0].pair(jsonpickle.decode(pk[3 + nb_attr + i]))).pow(jsonpickle.decode(sm[i])))
    verif = verif * (random_signature[0].pair(jsonpickle.decode(pk[1 + nb_attr]))).pow(st)

    #need to compute left side to check if it's equal to right side commitment using the bilinear function:
    left_side = random_signature[1].pair(jsonpickle.decode(pk[1 + nb_attr]))
    for i in disclosed_attributes:
        left_side = left_side * ((random_signature[0].pair(jsonpickle.decode(pk[3 + nb_attr + i]))).pow(-Bn.from_binary(disclosed_attributes[i].encode())))
    left_side = left_side / (random_signature[0].pair(jsonpickle.decode(pk[2 + nb_attr])))

    #check if verif == R and if left_side == right_side_commitment
    return ((R == verif) and (left_side == right_side_commit))



def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    
    """ Create a disclosure proof """
    nb_attr = len(credential[0])

    #pick random r and t in Zp
    r = G1M.order().random()
    t = G1M.order().random()

    creds = credential[0]
    cred_sig1, cred_sig2 = jsonpickle.decode(credential[1][0]), jsonpickle.decode(credential[1][1])

    #create random signature 
    random_signature = (cred_sig1.pow(r), (cred_sig2 * cred_sig1.pow(t)).pow(r))

    #putting all hidden and disclosed attributes in a dictionarry (to know which Yi corresponds to it)
    hidden_attr_index_dic = {}
    disclosed_attr_index_dic = {}
    for i, attr in enumerate(credential[0]):
       if attr in hidden_attributes:
           hidden_attr_index_dic[i] = attr
       else:
           disclosed_attr_index_dic[i] = attr

    #compute the commitment using all hidden attributes
    right_side_commit = (random_signature[0].pair(jsonpickle.decode(pk[1 + nb_attr]))).pow(t)

    for i in hidden_attr_index_dic:
       right_side_commit = right_side_commit * ((random_signature[0].pair(jsonpickle.decode(pk[3 + nb_attr + i]))).pow(Bn.from_binary(hidden_attr_index_dic[i].encode())))

    #create zero knowledge proof for the showing protocol
    proof = zero_knowledge_proof_showing_protocol(t, hidden_attr_index_dic, right_side_commit, pk, random_signature, message)

    #encode random signature
    random_signature = (jsonpickle.encode(random_signature[0]),jsonpickle.encode(random_signature[1]))
    return jsonpickle.encode(right_side_commit), random_signature, disclosed_attr_index_dic, proof


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    right_side_commit = disclosure_proof[0]
    random_signature = disclosure_proof[1]
    disclosed_attr_index_dic = disclosure_proof[2]
    proof = disclosure_proof[3]

    proof_verif = verify_non_interactive_proof_showing_protocol(proof,pk,right_side_commit,disclosed_attr_index_dic, random_signature, message)
    neutral_verif = jsonpickle.decode(random_signature[0]).is_neutral_element()

    return proof_verif and not neutral_verif
