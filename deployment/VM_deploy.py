import logging
import json
import multiprocessing
import paramiko
import os
import sys
import copy
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource.resources.models import DeploymentMode

from utils import *
from configs import *

SUBSCRIPTION_ID = ''

token = DefaultAzureCredential()

resource_client = ResourceManagementClient(
    credential=token,
    subscription_id=SUBSCRIPTION_ID
)

compute_client = ComputeManagementClient(
    credential=token,
    subscription_id=SUBSCRIPTION_ID
)


class VMManager:
# Used for client and SGX VMs
    template = None
    parameters = None
# Used for AMD VMs
    amd_template = None
    amd_parameters = None

    with open('./template_VM/template.json', 'r') as f:
        template = json.load(f)
    with open('./template_VM/parameters.json', 'r') as f:
        parameters = json.load(f)['parameters']
    with open('./template_AMD/template.json', 'r') as f:
        amd_template = json.load(f)
    with open('./template_AMD/parameters.json', 'r') as f:
        amd_parameters = json.load(f)['parameters']

    def __init__(self):
        pass

    @staticmethod
    def get_rg_name(group_id):
        return 'RG_{}'.format(group_id)

    @staticmethod
    def get_vm_name(group_id, vm_id):
        return 'VM-{}-{}'.format(locations[group_id], vm_id)
    
    @staticmethod
    def get_cvm_name(cvm):
        return 'VM-{}'.format(cvm)

    @staticmethod
    def get_vm_ip_name(vm_name):
        return '{}-ip'.format(vm_name)
    
    @staticmethod
    def get_deployment_name(vm_name):
        return 'deploy-{}'.format(vm_name)
    
    def deploy_VM(self, vm_type, group_id, vm_name):
        parameters = self.parameters
        template = self.template

        location = locations[group_id]
        parameters['location']['value'] = location
            
        nic_id = ''
        parameters['networkSecurityGroupId']['value'] = nic_id

        vnet_id = ''
        parameters['virtualNetworkId']['value'] = vnet_id

        rg_name = VMManager.get_rg_name(group_id)
        parameters['virtualMachineRG']['value'] = rg_name

        task_name = 'Deploy VM {} in location {}'.format(vm_name, location)

        parameters['publicIpAddressName']['value'] = VMManager.get_vm_ip_name(vm_name)

        parameters['virtualMachineName']['value'] = vm_name
        parameters['virtualMachineComputerName']['value'] = vm_name

        parameters['networkInterfaceName']['value'] = '{}-ni'.format(vm_name)

        parameters['virtualMachineSize']['value'] = vm_type

        deployment_name = VMManager.get_deployment_name(vm_name)

        run_task(task_name, lambda: resource_client.deployments.begin_create_or_update(
            rg_name,
            deployment_name,
            {
                "properties": {
                    "template": template,
                    "parameters": parameters,
                    "mode": DeploymentMode.incremental
                }
            }
        ))

    def deploy_client_VMs(self):
        for group_id in range(len(locations)):
            for vm_id in range(n_vm_each_loc):
                self.deploy_VM(client_vm_type, group_id, VMManager.get_vm_name(group_id, vm_id))
    
    def deploy_AMD_VM(self):
        vm_name = VMManager.get_cvm_name('AMD')
        run_task('Deploy VM {} in location {}'.format(vm_name, locations[cvm_group_id]), 
                 lambda: resource_client.deployments.begin_create_or_update(
                    VMManager.get_rg_name(cvm_group_id),
                    VMManager.get_deployment_name(vm_name),
                    {
                        "properties": {
                            "template": self.amd_template,
                            "parameters": self.amd_parameters,
                            "mode": DeploymentMode.incremental
                        }
                    }
        ))
        

    def deploy_CVMs(self):
        self.deploy_VM(sgx_vm_type, cvm_group_id, VMManager.get_cvm_name('SGX'))
        self.deploy_AMD_VM()

    @staticmethod
    def get_vm_ip(group_id, vm_name):
        return run_task('Fetch IP of VM {}'.format(vm_name),
                        lambda: resource_client.resources.get(
                            resource_group_name=VMManager.get_rg_name(group_id),
                            resource_provider_namespace='Microsoft.Network',
                            parent_resource_path='',
                            resource_type='publicIPAddresses',
                            resource_name=VMManager.get_vm_ip_name(vm_name),
                            api_version='2024-01-01'
                        ).properties['ipAddress']
                )   

    def get_client_vm_ips(self):
        vm_ips = []
        for vm_id in range(n_vm_each_loc):
            for group_id in range(len(locations)):
                vm_name = VMManager.get_vm_name(group_id, vm_id)
                ip = self.get_vm_ip(group_id, vm_name)
                vm_ips.append(ip)
        return vm_ips
    
    def get_cvm_ips(self):
        return (self.get_vm_ip(cvm_group_id, self.get_cvm_name('SGX')),
                self.get_vm_ip(cvm_group_id, self.get_cvm_name('AMD')))
    
    # @staticmethod
    # def reboot_vm(vm_name):
        # pass
    

class VMConnection:
    pkey = paramiko.Ed25519Key.from_private_key_file(pkey_path)

    def __init__(self):
        pass

    @staticmethod
    def connect(ip):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        try:
            repeat_try_task('Connect to {}'.format(ip),
                    max_n_try=6,
                    retry_interval=5,
                    task=lambda: ssh.connect(
                        hostname=ip,
                        port=22,
                        username='azureuser',
                        pkey=VMConnection.pkey
                    ))
        except Exception as e:
            logger.error('Connect to {} failed, ignore this VM: {}'.format(ip, e))
            return None
        else:
            return ssh

    @staticmethod
    def connect_clients(client_ips):
        client_conns = []
        for ip in client_ips:
            ssh = VMConnection.connect(ip)
            if ssh is not None:
                client_conns.append(ssh)
        return client_conns
    
    @staticmethod
    def connect_cvms(cvm_ips):
        cvm_conns = []
        for ip in cvm_ips:
            ssh = VMConnection.connect(ip)
            if ssh is None:
                exit(1)
            cvm_conns.append(
                ssh
            )
        return cvm_conns
    
    @staticmethod
    def close(conn):
        conn.close()


class ResourceDeployer:
    def __init__(self):
        pass

    @staticmethod
    def setup_all(ssh):
        ResourceDeployer.upload_source_to(ssh)
        ResourceDeployer.setup_env(ssh)
        ResourceDeployer.build(ssh)

    @staticmethod
    def upload_source_to(ssh):
        exec_command_sync(ssh, 'sudo rm -rf ./prot_mpc')
        sftp = ssh.open_sftp()
        run_task('Upload source files to {}'.format(ssh.get_transport().getpeername()),
                 lambda: sftp.put(local_source_path, remote_source_path))
        sftp.close()
    
    @staticmethod
    def setup_env(ssh):
        exec_command_sync_ignore_err(ssh, 'sudo apt install unzip')
        exec_command_sync(ssh, 'unzip -q {} && echo done'.format(remote_source_path))
        exec_command_sync_ignore_err(ssh, 'cd ./prot_mpc && chmod 777 ./setup && sudo ./setup')
    
    @staticmethod
    def build(ssh):
        exec_command_sync(ssh, 'cd ./prot_mpc && mkdir -p build && echo done')


class TaskManager:
    
    def __init__(self, client_conns, cvm_conns):
        assert(len(cvm_conns) == 2)
        self.client_conns = client_conns
        self.cvm_conns = cvm_conns

        self.peers = {}
        for conns in [self.client_conns, self.cvm_conns]:
            for conn in conns:
                self.peers.setdefault(conn.get_transport().getpeername()[0], conn)

    def run_task(self, task_name, task_config, **kargs):
        kargs.setdefault('enable_multiplexing', False)

        log_folder = './logs/{}'.format(task_name)
        try:
            os.mkdir(log_folder)
        except Exception:
            pass

        n_prot_mpc_client = task_config['client']['n_prot_mpc_client']

        task_config['client']['ip'] = []
        for client_id in range(n_prot_mpc_client):
            task_config['client']['ip'].append(
                self.client_conns[client_id%len(self.client_conns)].get_transport().getpeername()[0]
            )

        with open('./config.json', 'w') as config_file:
            json.dump(task_config, config_file, indent=4)
        
        with open('./types.h', 'w') as type_file:
            contents = 'using FieldType = Zp<1000000007>; \
                using ParamType = Parameter<FieldType, {}>; \
                using PolynomialType = Polynomial<FieldType, ParamType>; \
                static inline FieldType at(size_t id_in_group) {{\
                    return FieldType(id_in_group + 1);\
                }}'.format(task_config['parameter']['length'])
            type_file.write(contents)

        make_outs = []
        make_errs = []

        def upload_files(conn):
            sftp = conn.open_sftp()
            run_task('Upload config file to {}'.format(conn.get_transport().getpeername()),
                    lambda: sftp.put('./config.json', './prot_mpc/config.json'))
            run_task('Upload types.h to {}'.format(conn.get_transport().getpeername()),
                    lambda: sftp.put('./types.h', './prot_mpc/common/secagg/types.h'))
            sftp.close()
        process_pool = multiprocessing.Pool(PROCESS_POOL_SIZE)
        for conn in self.peers.values():
            upload_files(conn)
        process_pool.close()
        process_pool.join()

        for conn in self.peers.values():
            _, make_out, make_err = conn.exec_command(
                'mkdir -p ./prot_mpc/build && cd ./prot_mpc/build && rm -rf ./* && cmake -DNDEBUG={} -DSECAGG_TEST={} -DPROT_MPC_TEST={} .. && make && echo done'.format(
                    task_config['build']['ndebug'], task_config['build']['secagg_test'], task_config['build']['prot_mpc_test']
                ))
            make_outs.append(make_out)
            make_errs.append(make_err)
        for make_out in make_outs:
            make_out.read()
        for make_err in make_errs:
            make_err.read()

        _, out_sgx, err_sgx = self.cvm_conns[SGX].exec_command('cd ./prot_mpc/build && sudo ./sgx_server/host/host ../config.json')
        _, out_amd, err_amd = self.cvm_conns[AMD].exec_command('cd ./prot_mpc/build && ./amd_server/server ../config.json')
        
        partial_trust_end = task_config['client']['n_partial_trust']
        complete_trust_on_sgx_end = partial_trust_end + task_config['client']['n_complete_trust_on_SGX']
        complete_trust_on_amd_end = complete_trust_on_sgx_end + task_config['client']['n_complete_trust_on_AMD']
        not_trust_end = n_prot_mpc_client
        assert(complete_trust_on_amd_end <= not_trust_end)

        client_outs = []
        client_errs = []

        if not kargs['enable_multiplexing']:
            assert(n_prot_mpc_client <= len(self.client_conns))

        client_id = 0
        conn_id = 0
        while client_id < n_prot_mpc_client:
            if client_id < partial_trust_end:
                trust = Trust.PARTIAL_TRUST()
            elif client_id < complete_trust_on_sgx_end:
                trust = Trust.COMPLETE_TRUST(SGX)
            elif client_id < complete_trust_on_amd_end:
                trust = Trust.COMPLETE_TRUST(AMD)
            else:
                trust = Trust.NOT_TRUST()
            _, out, err = self.client_conns[conn_id].exec_command('cd ./prot_mpc/build && ./prot_mpc_client/prot_mpc_client {} {} ../config.json'.format(
                    client_id, trust
                ))
            client_outs.append(out)
            client_errs.append(err)
            client_id += 1
            conn_id += 1
            if conn_id == len(self.client_conns):
                conn_id = 0

        assert(len(client_outs) == n_prot_mpc_client and len(client_errs) == n_prot_mpc_client)
        
        sgx_logger = get_logger(os.path.join(log_folder, 'server_sgx.log'))
        sgx_logger.info(out_sgx.read().decode('utf-8'))
        sgx_logger.error(err_sgx.read().decode('utf-8'))

        amd_logger = get_logger(os.path.join(log_folder, 'server_amd.log'))
        amd_logger.info(out_amd.read().decode('utf-8'))
        amd_logger.error(err_amd.read().decode('utf-8'))

        for client_id in range(n_prot_mpc_client):
            client_logger = get_logger(os.path.join(log_folder, 'client_{}.log'.format(client_id)))
            client_logger.info(client_outs[client_id].read().decode('utf-8'))
            client_logger.error(client_errs[client_id].read().decode('utf-8'))

def deploy_and_setup_VM(vm_type, group_id, vm_name):
    logging.basicConfig(filename='./logs/{}'.format(vm_name),
                        filemode='w',
                        level=logging.INFO,
                        format=LOG_FORMAT,
                        datefmt=DATE_FORMAT)
    vm_manager = VMManager()
    vm_manager.deploy_VM(vm_type, group_id, vm_name)
    ip = repeat_try_task('Fetch IP of VM {}'.format(vm_name),
                         MAX_REQUEST_COUNT,
                         REQUEST_INTERVAL,
                         vm_manager.get_vm_ip,
                         group_id,
                         vm_name
                         )
    conn = repeat_try_task('Connect VM {}'.format(vm_name),
                        MAX_REQUEST_COUNT,
                        REQUEST_INTERVAL,
                        VMConnection.connect,
                        ip)
    ResourceDeployer.setup_all(conn)


if __name__ == '__main__':
    logger = logging.getLogger('vm_deploy_logger')
    hdl = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)
    hdl.setFormatter(fmt)
    logger.addHandler(hdl)
    logger.setLevel(logging.INFO)

    # process_pool = multiprocessing.Pool(PROCESS_POOL_SIZE)
    # for group_id in range(4):
    #     for vm_id in range(8):
    #         process_pool.apply_async(
    #             deploy_and_setup_VM,
    #             args=(client_vm_type, group_id, VMManager.get_vm_name(group_id, vm_id),)
    #         )
    # process_pool.apply_async(
    #     deploy_and_setup_VM,
    #     args=(amd_vm_type, cvm_group_id, VMManager.get_cvm_name('AMD'),)
    # )
    # process_pool.apply_async(
    #     deploy_and_setup_VM,
    #     args=(sgx_vm_type, cvm_group_id, VMManager.get_cvm_name('SGX'),)
    # )
    # process_pool.close()
    # process_pool.join()

    vm_manager = VMManager()

    client_vm_ips = vm_manager.get_client_vm_ips()
    cvm_ips = vm_manager.get_cvm_ips()

    client_vm_conns = VMConnection.connect_clients(client_vm_ips)
    cvm_conns = VMConnection.connect_cvms(cvm_ips)

    task_manager = TaskManager(client_vm_conns, cvm_conns)

    with open('./config_template.json', 'r') as f:
        basic_task_config = json.load(f)
    
    basic_task_config['server']['sgx']['ip'] = cvm_ips[0]
    basic_task_config['server']['amd']['ip'] = cvm_ips[1]
    basic_task_config['client']['ip'] = [conn.get_transport().getpeername() for conn in client_vm_conns]

    for n_client in [4, 8, 16, 32, 48, 64]:
        for prot_mpc_test, secagg_test in [(False, True)]:
            task_config = copy.deepcopy(basic_task_config)
            task_config['client']['n_prot_mpc_client'] = n_client
            task_config['parameter']['length'] = 20000

            task_config['build']['ndebug'] = True
            task_config['build']['prot_mpc_test'] = prot_mpc_test
            task_config['build']['secagg_test'] = secagg_test
            
            if prot_mpc_test:
                task_config['client']['n_partial_trust'] = n_client // 4
                task_config['client']['n_complete_trust_on_SGX'] = n_client // 4
                task_config['client']['n_complete_trust_on_AMD'] = n_client // 4
            else:
                task_config['client']['n_partial_trust'] = 0
                task_config['client']['n_complete_trust_on_SGX'] = 0
                task_config['client']['n_complete_trust_on_AMD'] = 0

            n_prot_mpc_client = task_config['client']['n_prot_mpc_client']
            n_partial_trust = task_config['client']['n_partial_trust']
            n_complete_trust_on_sgx = task_config['client']['n_complete_trust_on_SGX']
            n_complete_trust_on_amd = task_config['client']['n_complete_trust_on_AMD']
            n_not_trust = n_prot_mpc_client - n_partial_trust - n_complete_trust_on_sgx - n_complete_trust_on_amd

            for test_id in range(n_test_for_each_point):
                task_manager.run_task('{}-{}-{}-{}-{}-{}-{}-{}'.format(n_prot_mpc_client,
                                                            n_partial_trust,
                                                            n_complete_trust_on_sgx,
                                                            n_complete_trust_on_amd,
                                                            n_not_trust,
                                                            task_config['parameter']['length'],
                                                            task_config['build']['prot_mpc_test'],
                                                            test_id),
                                    task_config,
                                    enable_multiplexing=True)

    for n_trust in range(11):
        for prot_mpc_test, secagg_test in [(True, False)]:#, (False, True)]:
            task_config = copy.deepcopy(basic_task_config)
            task_config['client']['n_prot_mpc_client'] = 32
            task_config['parameter']['length'] = 20000

            task_config['build']['ndebug'] = True
            task_config['build']['prot_mpc_test'] = prot_mpc_test
            task_config['build']['secagg_test'] = secagg_test
            
            if prot_mpc_test:
                task_config['client']['n_partial_trust'] = n_trust
                task_config['client']['n_complete_trust_on_SGX'] = n_trust
                task_config['client']['n_complete_trust_on_AMD'] = n_trust
            else:
                task_config['client']['n_partial_trust'] = 0
                task_config['client']['n_complete_trust_on_SGX'] = 0
                task_config['client']['n_complete_trust_on_AMD'] = 0

            n_prot_mpc_client = task_config['client']['n_prot_mpc_client']
            n_partial_trust = task_config['client']['n_partial_trust']
            n_complete_trust_on_sgx = task_config['client']['n_complete_trust_on_SGX']
            n_complete_trust_on_amd = task_config['client']['n_complete_trust_on_AMD']
            n_not_trust = n_prot_mpc_client - n_partial_trust - n_complete_trust_on_sgx - n_complete_trust_on_amd

            for test_id in range(n_test_for_each_point):
                task_manager.run_task('{}-{}-{}-{}-{}-{}-{}-{}'.format(n_prot_mpc_client,
                                                            n_partial_trust,
                                                            n_complete_trust_on_sgx,
                                                            n_complete_trust_on_amd,
                                                            n_not_trust,
                                                            task_config['parameter']['length'],
                                                            task_config['build']['prot_mpc_test'],
                                                            test_id),
                                    task_config,
                                    enable_multiplexing=True)

    for prot_mpc_test, secagg_test in [(True, False)]:#, (False, True)]:
        task_config = copy.deepcopy(basic_task_config)
        task_config['client']['n_prot_mpc_client'] = 32
        task_config['parameter']['length'] = 20000

        task_config['build']['ndebug'] = True
        task_config['build']['prot_mpc_test'] = prot_mpc_test
        task_config['build']['secagg_test'] = secagg_test
        
        task_config['client']['n_partial_trust'] = 10
        task_config['client']['n_complete_trust_on_SGX'] = 11
        task_config['client']['n_complete_trust_on_AMD'] = 11

    for param_len in [600, 1200, 2500, 5000, 10000, 20000, 30000]:
        for prot_mpc_test, secagg_test in [(True, False), (False, True)]:
            task_config = copy.deepcopy(basic_task_config)
            task_config['client']['n_prot_mpc_client'] = 32
            task_config['parameter']['length'] = param_len

            task_config['build']['ndebug'] = True
            task_config['build']['prot_mpc_test'] = prot_mpc_test
            task_config['build']['secagg_test'] = secagg_test
            
            if prot_mpc_test:
                task_config['client']['n_partial_trust'] = 8
                task_config['client']['n_complete_trust_on_SGX'] = 8
                task_config['client']['n_complete_trust_on_AMD'] = 8
            else:
                task_config['client']['n_partial_trust'] = 0
                task_config['client']['n_complete_trust_on_SGX'] = 0
                task_config['client']['n_complete_trust_on_AMD'] = 0

            n_prot_mpc_client = task_config['client']['n_prot_mpc_client']
            n_partial_trust = task_config['client']['n_partial_trust']
            n_complete_trust_on_sgx = task_config['client']['n_complete_trust_on_SGX']
            n_complete_trust_on_amd = task_config['client']['n_complete_trust_on_AMD']
            n_not_trust = n_prot_mpc_client - n_partial_trust - n_complete_trust_on_sgx - n_complete_trust_on_amd

            for test_id in range(n_test_for_each_point):
                task_manager.run_task('{}-{}-{}-{}-{}-{}-{}-{}'.format(n_prot_mpc_client,
                                                            n_partial_trust,
                                                            n_complete_trust_on_sgx,
                                                            n_complete_trust_on_amd,
                                                            n_not_trust,
                                                            task_config['parameter']['length'],
                                                            task_config['build']['prot_mpc_test'],
                                                            test_id),
                                    task_config,
                                    enable_multiplexing=True)

    for n_client in [16, 24, 32, 40, 48, 56, 64]:
        for prot_mpc_test, secagg_test in [(True, False)]:
            task_config = copy.deepcopy(basic_task_config)
            task_config['client']['n_prot_mpc_client'] = n_client
            task_config['parameter']['length'] = 20000

            task_config['build']['ndebug'] = True
            task_config['build']['prot_mpc_test'] = prot_mpc_test
            task_config['build']['secagg_test'] = secagg_test
            
            if prot_mpc_test:
                x = n_client - 8
                task_config['client']['n_partial_trust'] = x - x//3 * 2
                task_config['client']['n_complete_trust_on_SGX'] = x//3
                task_config['client']['n_complete_trust_on_AMD'] = x//3
            else:
                exit(1)

            n_prot_mpc_client = task_config['client']['n_prot_mpc_client']
            n_partial_trust = task_config['client']['n_partial_trust']
            n_complete_trust_on_sgx = task_config['client']['n_complete_trust_on_SGX']
            n_complete_trust_on_amd = task_config['client']['n_complete_trust_on_AMD']
            n_not_trust = n_prot_mpc_client - n_partial_trust - n_complete_trust_on_sgx - n_complete_trust_on_amd

            for test_id in range(n_test_for_each_point):
                task_manager.run_task('{}-{}-{}-{}-{}-{}-{}-{}'.format(n_prot_mpc_client,
                                                            n_partial_trust,
                                                            n_complete_trust_on_sgx,
                                                            n_complete_trust_on_amd,
                                                            n_not_trust,
                                                            task_config['parameter']['length'],
                                                            task_config['build']['prot_mpc_test'],
                                                            test_id),
                                    task_config,
                                    enable_multiplexing=True)

    for conn in client_vm_conns:
        conn.close()

    for conn in cvm_conns:
        conn.close()
