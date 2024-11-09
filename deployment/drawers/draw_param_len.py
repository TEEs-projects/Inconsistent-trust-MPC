import json
import matplotlib.pyplot as plt

PARTIAL_TRUST_CLIENT_TIME = 0
TRUST_SGX_CLIENT_TIME = 1
TRUST_AMD_CLIENT_TIME = 2
NOT_TRUST_CLIENT_TIME = 3
SGX_SERVER_TIME = 4
AMD_SERVER_TIME = 5

if __name__ == '__main__':
    with open(r'logs\test_1103\results\param_len_prot.json', 'r') as f:
        prot = json.load(f)
    with open(r'logs\test_1103\results\param_len_secagg.json', 'r') as f:
        secagg = json.load(f)
    
    plt.figure(figsize=(20, 16), dpi=300)
    n_client = [600, 1200, 2500, 5000, 10000, 20000, 30000]#, 40000, 50000]
    n_client = list(map(lambda x: x*8/1024, n_client))
    # sgx_server_runtime = [n_client_prot[i][SGX_SERVER_TIME] for i in range(len(n_client))]
    # amd_server_runtime = [n_client_prot[i][AMD_SERVER_TIME] for i in range(len(n_client))]

    plt.plot(n_client,
             [prot[i][SGX_SERVER_TIME]/1000 for i in range(len(n_client))],
             c='blue',
             label='SGX Server', linewidth=3.0, marker='^', markersize=15, linestyle='--')
    print([prot[i][SGX_SERVER_TIME]/1000 for i in range(len(n_client))])
    plt.plot(n_client,
             [prot[i][AMD_SERVER_TIME]/1000 for i in range(len(n_client))],
             c='royalblue',
             label='AMD Server', linewidth=3.0, marker='s', markersize=15, linestyle='--')
    plt.plot(n_client,
            [prot[i][NOT_TRUST_CLIENT_TIME][0]/1000 for i in range(len(n_client))],
            c='teal',
            label=r'$\mathbb{P}_0$ clients', linewidth=3.0, marker='s', markersize=15)
    plt.plot(n_client,
            [prot[i][PARTIAL_TRUST_CLIENT_TIME][1]/1000 for i in range(len(n_client))],
            c='orange',
            label=r'$\mathbb{P}_1$ clients', linewidth=3.0, marker='s', markersize=15)
    # print([prot[i][PARTIAL_TRUST_CLIENT_TIME][1]/1000 for i in range(len(n_client))])
    plt.plot(n_client,
            [(prot[i][TRUST_SGX_CLIENT_TIME][1] + prot[i][TRUST_AMD_CLIENT_TIME][1])/2000 for i in range(len(n_client))],
            c='brown',
            label=r'$\mathbb{P}_2^1$ and $\mathbb{P}_2^2$ clients', linewidth=3.0, marker='s', markersize=15, linestyle='--')
    # print([prot[i][TRUST_SGX_CLIENT_TIME][1]/1000 for i in range(len(n_client))])
    plt.plot(n_client,
             [secagg[i][SGX_SERVER_TIME]/1000 for i in range(len(n_client))],
             c='red',
             label='Secagg Server', linewidth=3.0, marker='^', markersize=15)
    print([secagg[i][SGX_SERVER_TIME]/1000 for i in range(len(n_client))])
    plt.plot(n_client,
            [secagg[i][NOT_TRUST_CLIENT_TIME][0]/1000 for i in range(len(n_client))],
            c='skyblue',
            label='Secagg Client', linewidth=3.0, marker='^', markersize=15, linestyle='--')

    print([prot[i][SGX_SERVER_TIME]/secagg[i][SGX_SERVER_TIME] for i in range(len(n_client))])

    plt.legend(loc='best', fontsize=30)
    plt.xticks(size=48)
    plt.yticks(size=48)
    plt.ylim(0, 16.5)
    plt.xlabel("Size of parameters (KB)", fontdict={'size': 60})
    plt.ylabel("Running time (s)", fontdict={'size': 60})

    plt.savefig(r'drawers\param_len.png')
