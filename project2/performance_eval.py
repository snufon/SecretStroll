
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
import random
import string
import sys
import pandas as pd

import time

#generates random subscriptions names of length 8:
def generate_subscription():
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(8))

#### Computation and communication cost key generation ####
possible_subscriptions_nb = [1,5,10,20,50]
stats_key_gen_times = pd.DataFrame(columns = possible_subscriptions_nb)
stats_key_gen_com = pd.DataFrame(columns = possible_subscriptions_nb)

for nb_subsctiptions in possible_subscriptions_nb:
    times = []
    coms = []
    for i in range(25):
        subscriptions = [generate_subscription() for _ in range(nb_subsctiptions)] 
        server = Server()
        client = Client()

        start = time.time()
        secret,public = server.generate_ca(subscriptions + ["username"])
        end = time.time()

        #append measured times and bytes
        times.append(end-start)
        coms.append(sys.getsizeof(public))
    stats_key_gen_times[nb_subsctiptions] = times
    stats_key_gen_com[nb_subsctiptions] = coms

#save stats
stats_key_gen_times.to_csv("key_gen_times")
stats_key_gen_com.to_csv("key_gen_coms")

#### Computation and communication cost issuance of credentials ####
possible_subscriptions_nb = [1,5,10,20,50]
stats_issuance_times = pd.DataFrame(columns = possible_subscriptions_nb)
stats_issuance_com = pd.DataFrame(columns = possible_subscriptions_nb)

for nb_subsctiptions in possible_subscriptions_nb:
    times = []
    coms = []
    for i in range(25):
        subscriptions = [generate_subscription() for _ in range(nb_subsctiptions)] 
        server = Server()
        client = Client()

        secret,public = server.generate_ca(subscriptions + ["username"])


        start = time.time()
        issuance_request, state = client.prepare_registration(public, "Bob",subscriptions)

        signed_issue_request = server.process_registration(secret, public, issuance_request,"Bob", subscriptions)

        credentials = client.process_registration_response(public, signed_issue_request, state)

        end = time.time()     

        #append measured times and bytes   
        times.append(end-start)
        coms.append(sys.getsizeof(issuance_request) + sys.getsizeof(signed_issue_request))
    stats_issuance_times[nb_subsctiptions] = times
    stats_issuance_com[nb_subsctiptions] = coms

#save stats
stats_issuance_times.to_csv("issuance_times")
stats_issuance_com.to_csv("issuance_coms")

####Computation and communication cost showing credentials####
possible_subscriptions_nb = [1,5,10,20,50]
stats_showing_times = pd.DataFrame(columns = possible_subscriptions_nb)
stats_showing_com = pd.DataFrame(columns = possible_subscriptions_nb)

for nb_subsctiptions in possible_subscriptions_nb:
    times = []
    coms = []
    for i in range(25):
        subscriptions = [generate_subscription() for _ in range(nb_subsctiptions)] 
        server = Server()
        client = Client()

        
        secret,public = server.generate_ca(subscriptions + ["username"])



        issuance_request, state = client.prepare_registration(public, "Bob",subscriptions)

        signed_issue_request = server.process_registration(secret, public, issuance_request,"Bob", subscriptions)

        credentials = client.process_registration_response(public, signed_issue_request, state)

      

        lat,lon = 46.52345, 6.57890
        start = time.time()

        disc_proof_request = client.sign_request(public, credentials, (f"{lat},{lon}").encode("utf-8"), subscriptions)  

        end = time.time()   
        #append measured times and bytes  
        times.append(end-start)
        coms.append(sys.getsizeof(disc_proof_request))
    stats_showing_times[nb_subsctiptions] = times
    stats_showing_com[nb_subsctiptions] = coms


#save stats
stats_showing_times.to_csv("showing_times")
stats_showing_com.to_csv("showing_coms")

#### Computation and communication cost verifying credentials ####
possible_subscriptions_nb = [1,5,10,20,50]
stats_verify_times = pd.DataFrame(columns = possible_subscriptions_nb)

for nb_subsctiptions in possible_subscriptions_nb:
    times = []
    for i in range(25):
        subscriptions = [generate_subscription() for _ in range(nb_subsctiptions)] 
        server = Server()
        client = Client()

        
        secret,public = server.generate_ca(subscriptions + ["username"])



        issuance_request, state = client.prepare_registration(public, "Bob",subscriptions)

        signed_issue_request = server.process_registration(secret, public, issuance_request,"Bob", subscriptions)

        credentials = client.process_registration_response(public, signed_issue_request, state)

      

        lat,lon = 46.52345, 6.57890

        disc_proof_request = client.sign_request(public, credentials, (f"{lat},{lon}").encode("utf-8"), subscriptions) 

        start = time.time()
        verif = server.check_request_signature(public, (f"{lat},{lon}").encode("utf-8"), subscriptions, disc_proof_request)
 

        end = time.time()  
        assert verif 
        #append measured times
        times.append(end-start)
    stats_verify_times[nb_subsctiptions] = times

#save stats
stats_verify_times.to_csv("verify_times")


