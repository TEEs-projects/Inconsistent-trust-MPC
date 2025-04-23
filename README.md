# Prerequisites
- OS: Ubuntu 20.04-LTS 64-bit
- An SGX-enabled system installed with [Open Enclave SDK](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_20.04.md)
- An Azure AMD Confidential VM (Not mandatory. Currently, we attest the AMD VM [manually](https://github.com/Azure/confidential-computing-cvm-guest-attestation/blob/main/cvm-guest-attestation.md). The codes deployed in this VM can be deployed in normal machines.)
- Tools: CMake 3.16.3, clang-11, clang++-11, Python 3.8.10

# Local Test on an SGX machine
1. Build and install MbedTLS
    ```
    cd protocol/prot_mpc/mbedtls && cmake -DENABLE_TESTING=Off . && sudo make install
    ```

2. Create directories for build and log files
    ```
    cd .. && mkdir build && mkdir logs
    ```

3. Run a local test
    ```
    python3 local_test.py
    ```
    The Python script launches multiple processes to create an SGX server, a simulated AMD server, and simulated clients. These processes run the protocol with randomized inputs. The logs are recorded in the `logs` directory.

### Configure a local test
 The file `protocol/prot_mpc/config.json` contains the configuration for a local test. Below are the configurable fields in a local test. Other fields are only used in tests on WAN.

 | Field      | Description |
| ----------- | ----------- |
| `n_prot_mpc_client`      | Total number of clients       |
| `n_partial_trust`   | Number of $\mathbb{P}_1$ clients        |
| `n_complete_trust_on_SGX`   | Number of $\mathbb{P}_2^1$ clients        |
| `n_complete_trust_on_AMD`   | Number of $\mathbb{P}_2^2$ clients        |

# Deploy the protocols on WAN

The protocols can be deployed on the Azure platform. 3 types of machines are involved.

- `Standard_B1s`: This type of machines runs clients in the protocols.
- `Standard_DC1s_v3`: This type of machines runs the SGX server and the server of $\texttt{SwiftAgg+}.$
- `Standard_DCas_v5`: This type of machines runs the AMD server.

1. Configure `deployment/VM_deploy.py`. Assign the variable `SUBSCRIPTION_ID` with an Azure account subscription ID.
2. Configure `deployment/configs.py`. Assign the variable `pkey_path` with the private key to log in to VMs on Azure. Assign the variable `source_file_name` with the path to the directory `protocol/prot_mpc`. 
3. Configure `deployment/template_VM/parameters.json`. Fill the empty fields in the JSON file with VM info. If not sure about these values, create a new VM on Azure manually and use the info of the new VM. Similarly, configure `deployment/template_SGX/parameters.json` and `deployment/template_AMD/parameters.json`.
4. Use the script `deployment/VM_deploy.py` to deploy the above 3 types of machines. The geographical distributions of machines can be configured in `deployment/config.py`. Before deploying the machines, make sure that an Azure account has been logged in the current CLI and the account can access the 3 types of machines in the regions.
5. Use the same script `deployment/VM_deploy.py` to run tests. The settings of tests, including the number of different types of clients and parameter lengths, are configurable in the script by configuring the variable `basic_task_config`.

