import os
import json
import copy

from configs import *

def parse(line):
    return int(line.split()[-1][:-3])

def analyze_unit_time(client_log_path, prot_mpc_test, trust_tee):
    with open(client_log_path, 'r') as f:
        lines = f.readlines()
    if prot_mpc_test:
        if trust_tee:
            return [parse(lines[x]) for x in [17, 20, 22]]
        else:
            return [parse(lines[x]) for x in [17, 25, 28]]
    else:
        return [parse(lines[x]) for x in [23, 26]]

def analyze_client_time(client_log_path, prot_mpc_test, trust_tee):
    with open(client_log_path, 'r') as f:
        lines = f.readlines()
    try:
        if prot_mpc_test:
            if trust_tee:
                return [parse(lines[x]) for x in [23, 24]]
            else:
                return [parse(lines[x]) for x in [26, 27]]
        else:
            return [parse(lines[x]) for x in [24, 25]]
    except Exception:
        raise

def analyze_server_time(server_log_path):
    with open(server_log_path, 'r') as f:
        line = f.readlines()[-3]
    try:
        return parse(line)
    except Exception:
        raise


class TestPointResult:
    def __init__(self):
        self.not_trust_client_time = None
        self.partial_trust_client_time = None
        self.trust_SGX_client_time = None
        self.trust_AMD_client_time = None
        self.AMD_server_time = None
        self.SGX_server_time = None

PARTIAL_TRUST_CLIENT_TIME = 0
TRUST_SGX_CLIENT_TIME = 1
TRUST_AMD_CLIENT_TIME = 2
NOT_TRUST_CLIENT_TIME = 3
SGX_SERVER_TIME = 4
AMD_SERVER_TIME = 5

def analyze_unit_test(data_folder, task_config):
    n_prot_mpc_client = task_config['client']['n_prot_mpc_client']
    n_partial_trust = task_config['client']['n_partial_trust']
    n_complete_trust_on_sgx = task_config['client']['n_complete_trust_on_SGX']
    n_complete_trust_on_amd = task_config['client']['n_complete_trust_on_AMD']
    total_trust = n_partial_trust + n_complete_trust_on_sgx + n_complete_trust_on_amd
    n_not_trust = n_prot_mpc_client - total_trust

    COMMIT = 0
    SEND_INPUT = 1
    TOTAL = 2
    COMPUTE = 3
    RECEIVE_INPUT = 4

    if task_config['build']['prot_mpc_test']:
        result = [0, 0, 0, 0, 0]
    else:
        result = [0, 0]

    n_valid_test = 0
    for test_id in range(n_test_for_each_point):
        try:
            test_name = '{}-{}-{}-{}-{}-{}-{}-{}'.format(n_prot_mpc_client,
                                                        n_partial_trust,
                                                        n_complete_trust_on_sgx,
                                                        n_complete_trust_on_amd,
                                                        n_not_trust,
                                                        task_config['parameter']['length'],
                                                        task_config['build']['prot_mpc_test'],
                                                        test_id)
            test_folder = os.path.join(data_folder, test_name)

            if task_config['build']['prot_mpc_test']:
                for client_id in range(total_trust):
                    client_file_path = os.path.join(test_folder, 'client_{}.log'.format(client_id))
                    client_res = analyze_unit_time(client_file_path, True, True)
                    result[COMMIT] += client_res[0]
                    result[SEND_INPUT] += client_res[1]
                    result[RECEIVE_INPUT] += client_res[2]

                for client_id in range(total_trust, n_prot_mpc_client):
                    client_file_path = os.path.join(test_folder, 'client_{}.log'.format(client_id))
                    client_res = analyze_unit_time(client_file_path, True, False)
                    result[COMMIT] += client_res[0]
                    result[TOTAL] += client_res[1]
                    result[COMPUTE] += client_res[2]
            else:
                for client_id in range(n_prot_mpc_client):
                    client_file_path = os.path.join(test_folder, 'client_{}.log'.format(client_id))
                    client_res = analyze_unit_time(client_file_path, False, False)
                    result[0] += client_res[0]
                    result[1] += client_res[1]
        except Exception as e:
            print(e)
        else:
            n_valid_test += 1
    assert(n_valid_test > 0)
    
    result = list(map(lambda x : x / n_valid_test, result))

    if task_config['build']['prot_mpc_test']:
        result[COMMIT] /= n_prot_mpc_client
        result[SEND_INPUT] /= total_trust
        result[RECEIVE_INPUT] /= total_trust
        result[COMPUTE] /= n_not_trust
        result[TOTAL] /= n_not_trust
    else:
        result[0] /= n_prot_mpc_client
        result[1] /= n_prot_mpc_client
        
    return result

def analyze_test_point(data_folder, task_config):
    n_prot_mpc_client = task_config['client']['n_prot_mpc_client']
    n_partial_trust = task_config['client']['n_partial_trust']
    n_complete_trust_on_sgx = task_config['client']['n_complete_trust_on_SGX']
    n_complete_trust_on_amd = task_config['client']['n_complete_trust_on_AMD']
    n_not_trust = n_prot_mpc_client - n_partial_trust - n_complete_trust_on_sgx - n_complete_trust_on_amd
    client_counts = [n_partial_trust, n_complete_trust_on_sgx, n_complete_trust_on_amd, n_not_trust]

    prot_mpc_test = task_config['build']['prot_mpc_test']
    result = [[0, 0], [0, 0], [0, 0], [0, 0], 0, 0]
    n_valid_test = 0
    for test_id in range(n_test_for_each_point):
        try:
            test_name = '{}-{}-{}-{}-{}-{}-{}-{}'.format(n_prot_mpc_client,
                                            n_partial_trust,
                                            n_complete_trust_on_sgx,
                                            n_complete_trust_on_amd,
                                            n_not_trust,
                                            task_config['parameter']['length'],
                                            task_config['build']['prot_mpc_test'],
                                            test_id)
            test_folder = os.path.join(data_folder, test_name)
            for (index, server) in [(SGX_SERVER_TIME, 'sgx'), (AMD_SERVER_TIME, 'amd')]:
                server_file_path = os.path.join(test_folder, 'server_{}.log'.format(server))
                result[index] += analyze_server_time(server_file_path)

            endpoints = [0] * (len(client_counts) + 1)
            for i in range(len(client_counts)):
                endpoints[i + 1] = endpoints[i] + client_counts[i]

            # deal with trusts
            for i in range(len(endpoints) - 2):
                for client_id in range(endpoints[i], endpoints[i+1]):
                    client_file_path = os.path.join(test_folder, 'client_{}.log'.format(client_id))
                    client_res = analyze_client_time(client_file_path, prot_mpc_test, True)
                    result[i][0] += client_res[0]
                    result[i][1] += client_res[1]
            #deal with not trust
            for client_id in range(endpoints[-2], n_prot_mpc_client):
                client_file_path = os.path.join(test_folder, 'client_{}.log'.format(client_id))
                client_res = analyze_client_time(client_file_path, prot_mpc_test, False)
                result[-3][0] += client_res[0]
                result[-3][1] += client_res[1]
        except Exception as e:
            print(e)
        else:
            n_valid_test += 1
    assert(n_valid_test > 0)

    for i in range(len(client_counts)):
        if client_counts[i] > 0:
            result[i][0] /= client_counts[i] * n_valid_test
            result[i][1] /= client_counts[i] * n_valid_test

    result[SGX_SERVER_TIME] /= n_valid_test
    result[AMD_SERVER_TIME] /= n_valid_test
    
    return result


if __name__ == '__main__':
    with open('./config_template.json', 'r') as f:
        basic_config = json.load(f)
    
    # number of clients
    config = copy.deepcopy(basic_config)
    data_folder = r'logs\test_1103\n_client'

    config['client']['n_prot_mpc_client'] = 32

    results_fixed_not_trust = []
    results_n_client_prot = []
    results_n_client_secagg = []
    for n_prot_mpc_client in [4, 8, 16, 32, 48, 64]:
        config['client']['n_prot_mpc_client'] = n_prot_mpc_client
        config['build']['prot_mpc_test'] = True

        n_trust = n_prot_mpc_client // 4
        config['client']['n_partial_trust'] = n_trust
        config['client']['n_complete_trust_on_SGX'] = n_trust
        config['client']['n_complete_trust_on_AMD'] = n_trust
        results_n_client_prot.append(analyze_test_point(data_folder, config))

        config['build']['prot_mpc_test'] = False
        config['client']['n_partial_trust'] = 0
        config['client']['n_complete_trust_on_SGX'] = 0
        config['client']['n_complete_trust_on_AMD'] = 0
        results_n_client_secagg.append(analyze_test_point(data_folder, config))

    for n_prot_mpc_client in [16, 24, 32, 40, 48, 56, 64]:
        config['client']['n_prot_mpc_client'] = n_prot_mpc_client
        config['build']['prot_mpc_test'] = True

        x = n_prot_mpc_client - 8
        config['client']['n_partial_trust'] = x - x//3 * 2
        config['client']['n_complete_trust_on_SGX'] = x//3
        config['client']['n_complete_trust_on_AMD'] = x//3

        results_fixed_not_trust.append(analyze_test_point(data_folder, config))
    
    print(results_n_client_prot)
    print('')
    print(results_fixed_not_trust)

    n_trust
    results_n_trust = []

    config['client']['n_prot_mpc_client'] = 32
    config['build']['prot_mpc_test'] = False
    config['client']['n_partial_trust'] = 0
    config['client']['n_complete_trust_on_SGX'] = 0
    config['client']['n_complete_trust_on_AMD'] = 0
    results_n_trust.append(analyze_test_point(data_folder, config))
    config['build']['prot_mpc_test'] = True
    for n_trust in range(1, 11):
        config['client']['n_partial_trust'] = n_trust
        config['client']['n_complete_trust_on_SGX'] = n_trust
        config['client']['n_complete_trust_on_AMD'] = n_trust   
        results_n_trust.append(analyze_test_point(data_folder, config))

    config['client']['n_partial_trust'] = 10
    config['client']['n_complete_trust_on_SGX'] = 11
    config['client']['n_complete_trust_on_AMD'] = 11
    results_n_trust.append(analyze_test_point(data_folder, config))

    # with open(r'logs\test_1103\results\fixed_not_trust.json', 'w') as f:
    #     json.dump(results_fixed_not_trust, f)

    # with open(r'logs\test_1103\results\n_client_prot.json', 'w') as f:
    #     json.dump(results_n_client_prot, f)

    # with open(r'logs\test_1103\results\n_client_secagg.json', 'w') as f:
    #     json.dump(results_n_client_secagg, f)

    # with open(r'logs\test_1103\results\n_trust.json', 'w') as f:
    #     json.dump(results_n_trust, f)

    # config = copy.deepcopy(basic_config)
    # data_folder = r'logs'
    # config['client']['n_prot_mpc_client'] = 32
    # config['parameter']['length'] = 20000

    # config['build']['prot_mpc_test'] = True

    n_trust = 32 // 4
    config['client']['n_partial_trust'] = n_trust
    config['client']['n_complete_trust_on_SGX'] = n_trust
    config['client']['n_complete_trust_on_AMD'] = n_trust
    res = analyze_unit_test(data_folder, config)
    print(res, res[2]-res[0]-res[3])
    print(res[0]/sum(res), res[4]/sum(res))

    config['build']['prot_mpc_test'] = False
    config['client']['n_partial_trust'] = 0
    config['client']['n_complete_trust_on_SGX'] = 0
    config['client']['n_complete_trust_on_AMD'] = 0
    res = analyze_unit_test(data_folder, config)
    print(res, res[0]-res[1])
    
    # config['client']['n_prot_mpc_client'] = 32
    results_param_len_prot = []
    results_param_len_secagg = []
    config['client']['n_prot_mpc_client'] = 32
    for param_len in [600, 1200, 2500, 5000, 10000, 20000, 30000]:
        config['parameter']['length'] = param_len

        config['build']['prot_mpc_test'] = True

        n_trust = 32 // 4
        config['client']['n_partial_trust'] = n_trust
        config['client']['n_complete_trust_on_SGX'] = n_trust
        config['client']['n_complete_trust_on_AMD'] = n_trust
        results_param_len_prot.append(analyze_test_point(data_folder, config))

        config['build']['prot_mpc_test'] = False
        config['client']['n_partial_trust'] = 0
        config['client']['n_complete_trust_on_SGX'] = 0
        config['client']['n_complete_trust_on_AMD'] = 0
        results_param_len_secagg.append(analyze_test_point(data_folder, config))
    
    # with open(r'logs\test_1103\results\param_len_prot.json', 'w') as f:
    #     json.dump(results_param_len_prot, f)

    # with open(r'logs\test_1103\results\param_len_secagg.json', 'w') as f:
    #     json.dump(results_param_len_secagg, f)
    
    # for i in range(len(results_param_len_prot)):
    #     print(results_param_len_prot[i][4], results_param_len_secagg[i][4])
