import json
import matplotlib.pyplot as plt

PARTIAL_TRUST_CLIENT_TIME = 0
TRUST_SGX_CLIENT_TIME = 1
TRUST_AMD_CLIENT_TIME = 2
NOT_TRUST_CLIENT_TIME = 3
SGX_SERVER_TIME = 4
AMD_SERVER_TIME = 5

if __name__ == '__main__':
    with open(r'logs\test_1103\results\n_client_prot.json', 'r') as f:
        prot = json.load(f)
    with open(r'logs\test_1103\results\n_client_secagg.json', 'r') as f:
        secagg = json.load(f)
    
    plt.figure(figsize=(15, 12), dpi=300)
    n_client = [4, 8, 16, 32, 48, 64]
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
    print([prot[i][PARTIAL_TRUST_CLIENT_TIME][1]/1000 for i in range(len(n_client))])
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

    plt.legend(loc='best', fontsize=32)
    plt.xticks(size=36)
    plt.yticks(size=36)
    plt.ylim(0, 28)
    plt.xlabel("Number of clients", fontdict={'size': 48})
    plt.ylabel("Running time (s)", fontdict={'size': 48})

    plt.savefig(r'drawers\n_client.png')
