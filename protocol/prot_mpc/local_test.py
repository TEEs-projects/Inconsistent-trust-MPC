import os
import json
from multiprocessing import Process

class Trust:
    SGX = 0
    AMD = 1

    @staticmethod
    def NOT_TRUST():
        return 0
    
    @staticmethod
    def PARTIAL_TRUST():
        return 1
    
    @staticmethod
    def COMPLETE_TRUST(tee_id):
        return 2 + tee_id

def launch_sgx_server():
    cmd = 'cd build && ./sgx_server/host/host ../config.json > ../logs/sgx_server.log'
    print(cmd)
    os.system(cmd)

def launch_amd_server():
    cmd = 'cd build && ./amd_server/server ../config.json > ../logs/amd_server.log'
    print(cmd)
    os.system(cmd)

def launch_clients(client_id, trust):
    cmd = ('cd build && ./prot_mpc_client/prot_mpc_client {} {} ../config.json > ../logs/client{}.log').format(client_id, trust, client_id)
    print(cmd)
    os.system(cmd)

if __name__ == '__main__':
    with open('config.json', 'r') as f:
        config = json.loads(f.read())

    n_prot_mpc_client = config['client']['n_prot_mpc_client']
    n_partial_trust = config['client']['n_partial_trust']
    n_complete_trust_on_sgx = config['client']['n_complete_trust_on_SGX']
    n_complete_trust_on_amd = config['client']['n_complete_trust_on_AMD']

    assert(n_prot_mpc_client >= n_partial_trust + n_complete_trust_on_sgx + n_complete_trust_on_amd)
    # assert(len(config['client']['ip']) == n_prot_mpc_client)

    os.system('cd build && rm -rf ./* && cmake -DNDEBUG=True -DSECAGG_TEST=False -DPROT_MPC_TEST=True .. && make')

    childs = []
    childs.append(
        Process(target=launch_sgx_server, args=())
    )
    childs.append(
        Process(target=launch_amd_server, args=())
    )

    start = 0

    for i in range(n_partial_trust):
        childs.append(
            Process(target=launch_clients, args=(start + i, Trust.PARTIAL_TRUST()))
        )
    start += n_partial_trust
    
    for i in range(n_complete_trust_on_sgx):
        childs.append(
            Process(target=launch_clients, args=(start + i, Trust.COMPLETE_TRUST(Trust.SGX)))
        )
    start += n_complete_trust_on_sgx
    
    for i in range(n_complete_trust_on_amd):
        childs.append(
            Process(target=launch_clients, args=(start + i, Trust.COMPLETE_TRUST(Trust.AMD)))
        )
    start += n_complete_trust_on_amd

    for i in range(start, n_prot_mpc_client):
        childs.append(
            Process(target=launch_clients, args=(i, Trust.NOT_TRUST()))
        )
    
    for child in childs:
        child.start()
    
    for child in childs:
        child.join()
