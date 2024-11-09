pkey_path = r''
source_file_name = ''
local_source_path = r''.format(source_file_name)
remote_source_path = r'{}'.format(source_file_name)

locations = ['brazilsouth', 'northeurope', 'japaneast', 'eastus']
n_vm_each_loc = 8
client_vm_type = 'Standard_B1s'

cvm_group_id = 1
sgx_vm_type = 'Standard_DC1s_v3'
amd_vm_type = 'Standard_DC2as_v5'

MAX_REQUEST_COUNT = 10
REQUEST_INTERVAL = 10

PROCESS_POOL_SIZE = 34

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%m/%d/%Y %H:%M:%S %p"

SGX = 0
AMD = 1

n_test_for_each_point = 3

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
