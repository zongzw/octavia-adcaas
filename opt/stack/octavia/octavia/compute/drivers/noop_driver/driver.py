# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import base64
from datetime import datetime
import json
import multiprocessing

from oslo_log import log as logging
from oslo_utils import uuidutils

from octavia.common import constants
from octavia.common import data_models
from octavia.compute import compute_base as driver_base
from octavia.network import data_models as network_models

import requests
import time

LOG = logging.getLogger(__name__)


class AdcaasDriver:
    def __init__(self):
        rip = '183.84.2.168'
        # rip = '10.250.18.123'

        self.adcaas_server = "%s:3000" % rip
        self.username = "zongzw"
        password_b64 = "em9uZ3p3MTIz"
        self.password = str(base64.b64decode(password_b64), encoding='utf8')

        self.tenant_id = "610be7617fff469c88b71301cffd4c06"

        self.identity_url = 'http://%s:5000/v3/auth/tokens' % rip
        self.asg_url = "https://%s:8443/mgmt/shared/TrustedProxy" % rip

        self.token = self._get_token()

    def _get_token(self):

        url = self.identity_url

        headers = {
            'Content-Type': 'application/json'
        }

        payload_json = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "domain": {"name": "Default"},
                            "password": self.password
                        }
                    }
                },
                "scope": {
                    "project": {
                        "domain": {"name": "Default"},
                        "id": self.tenant_id
                    }
                }
            }
        }

        payload = json.dumps(payload_json)
        response = requests.request("POST", url, headers=headers, data=payload)

        if (response.status_code != 201):
            raise Exception('Failed to get token')

        LOG.debug(response.text.encode('utf8'))
        # response_json = json.loads(response.text.encode('utf8'))
        # tenant_id = response_json['token']['project']['id']
        token = response.headers['X-Subject-Token']

        return token

    def ping(self):

        url = "http://%s/ping" % self.adcaas_server

        payload = {}
        headers = {
            'Content-Type': 'application/json'
        }

        response = requests.request("GET", url, headers=headers, data=payload)

        LOG.debug(response.text.encode('utf8'))
        return response.text.encode('utf8')

    def create_adc(self):

        url = "http://%s/adcaas/v1/adcs" % self.adcaas_server

        payload_json = {
            "name": "octavia-inst-%s" % datetime.now().strftime("%Y-%m-%d-%H-%M-%S"),
            "description": "adc for test",
            "type": "VE",
            "networks": {
                "mgmt1": {
                    "type": "mgmt",
                    "networkId": "e12b30b7-d0d1-47f2-9be6-346913749ebc"
                },
                "failover1": {
                    "type": "ha",
                    "networkId": "798b1b24-1bd5-481f-bda9-ec1e65cb4ab9"
                },
                "internal1": {
                    "type": "int",
                    "networkId": "0fe91840-61a2-4a53-af54-1de59b6fde2b"
                },
                "external2": {
                    "type": "ext",
                    "networkId": "655a8581-3771-43b4-8cb4-2df01f0fa25c"
                }
            },
            "compute": {
                "imageRef": "0c571ff7-00ff-4e27-9f78-37e8dd31ef6d",
                "flavorRef": "201906"
            }
        }

        payload = json.dumps(payload_json)

        headers = {
            'x-auth-token': self.token,
            'tenant-id': self.tenant_id,
            'Content-Type': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, data=payload)

        if (int(response.status_code / 200) != 1):
            raise Exception("failed to create adc")

        response_json = json.loads(response.text.encode('utf8'))

        LOG.debug(response.text.encode('utf8'))
        return response_json['adc']['id']

    def get_adc_status(self, adc_id):

        url = "http://%s/adcaas/v1/adcs/%s" % (self.adcaas_server, adc_id)

        payload = {}
        headers = {
            'x-auth-token': self.token,
            'tenant-id': self.tenant_id,
            'Content-Type': 'application/json'
        }

        response = requests.request("GET", url, headers=headers, data=payload)

        if (response.status_code != 200):
            raise Exception("failed to get adc status.")
        
        LOG.debug(response.text.encode('utf8'))

        response_json = json.loads(response.text.encode('utf8'))

        
        return response_json['adc']['status']

    def delete_adc(self, adc_id):
        url = "http://%s/adcaas/v1/adcs/%s" % (self.adcaas_server, adc_id)

        payload = {}
        headers = {
            'x-auth-token': self.token,
            'tenant-id': self.tenant_id,
            'Content-Type': 'application/json'
        }

        response = requests.request(
            "DELETE", url, headers=headers, data=payload)

        LOG.debug(response.text.encode('utf8'))

    def setup_adc(self, adc_id):
        url = "http://%s/adcaas/v1/adcs/%s/setup" % (
            self.adcaas_server, adc_id)

        payload = {}
        headers = {
            'x-auth-token': self.token,
            'tenant-id': self.tenant_id,
            'Content-Type': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, data=payload)

        LOG.debug(response.text.encode('utf8'))
        return response.text.encode('utf8')

    def wait_for_status(self, adc_id, status):
        for _ in range(0, 100):
            try:
                s = self.get_adc_status(adc_id)
                LOG.debug('adc: %s status: %s' % (adc_id, s))
                if (s == status):
                    return
            except Exception as e:
                LOG.error("failed to get status, retring.: %s" % str(e))
            
            time.sleep(5)

        raise Exception("timeout for waiting adc: %s to %s" % (adc_id, status))

    def get_adc_ips(self, adc_id):

        url = "http://%s/adcaas/v1/adcs/%s" % (self.adcaas_server, adc_id)

        payload = {}
        headers = {
            'x-auth-token': self.token,
            'tenant-id': self.tenant_id,
            'Content-Type': 'application/json'
        }

        response = requests.request("GET", url, headers=headers, data=payload)

        if response.status_code != 200:
            raise Exception("failed to get adc status.")
        
        LOG.debug(response.text.encode('utf8'))

        response_json = json.loads(response.text.encode('utf8'))

        ips = {}
        netkeys = response_json['adc']['networks']
        netvalues = response_json['adc']['management']['networks']
        for k in netkeys.keys():
            ips[netkeys[k]["type"]] = netvalues[k]['fixedIp']

        return (
            ips['mgmt'],
            ips['ext'],
            # ips['int'],
            # ips['ha']
        )

    def deploy(self, adc_mgmt_ip, adc_ext_ip):
        url = self.asg_url

        payload_json = {
            "method": "Post",
            "uri": "https://%s:443/mgmt/shared/appsvcs/declare" % adc_mgmt_ip,
            "body": {
                "class": "AS3",
                "action": "deploy",
                "declaration": {
                    "class": "ADC",
                    "schemaVersion": "3.0.0",
                    "DF34445635634563": {
                        "class": "Tenant",
                        "label": "23423252",
                        "onboarding": {
                            "class": "Application",
                            "template": "generic",
                            "service": {
                                "class": "Service_HTTP",
                                "virtualAddresses": [
                                    adc_ext_ip
                                ],
                                "pool": "web_pool"
                            },
                            "web_pool": {
                                "class": "Pool",
                                "monitors": ["http"],
                                "members": [
                                    {
                                        "servicePort": 80,
                                        "serverAddresses": [
                                            "10.250.16.131"
                                        ]
                                    },
                                    {
                                        "servicePort": 81,
                                        "serverAddresses": [
                                            "10.250.16.130"
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }

        payload = json.dumps(payload_json)

        headers = {
            'Authorization': 'Basic YWRtaW46YWRtaW4=',
            'Content-Type': 'application/json'
        }

        response = requests.request(
            "POST", url, headers=headers, data=payload, verify=False)

        LOG.debug(response.text.encode('utf8'))


def start_adcaas_work(adc_id):
    adcinst = AdcaasDriver()

    adcinst.wait_for_status(adc_id, 'ONBOARDED')
    adcinst.setup_adc(adc_id)
    adcinst.wait_for_status(adc_id, 'ACTIVE')

    (adc_mgmt_ip, adc_ext_ip) = adcinst.get_adc_ips(adc_id)
    LOG.debug("mgmt ip: %s, ext ip: %s" % (adc_mgmt_ip, adc_ext_ip))

    adcinst.deploy(adc_mgmt_ip, adc_ext_ip)


class NoopManager(object):
    def __init__(self):
        super(NoopManager, self).__init__()
        self.computeconfig = {}

    def build(self, name="amphora_name", amphora_flavor=None,
              image_id=None, image_tag=None, image_owner=None,
              key_name=None, sec_groups=None, network_ids=None,
              config_drive_files=None, user_data=None, port_ids=None,
              server_group_id=None, availability_zone=None):
        LOG.debug("Compute %s no-op, build name %s, amphora_flavor %s, "
                  "image_id %s, image_tag %s, image_owner %s, key_name %s, "
                  "sec_groups %s, network_ids %s, config_drive_files %s, "
                  "user_data %s, port_ids %s, server_group_id %s, "
                  "availability_zone %s",
                  self.__class__.__name__,
                  name, amphora_flavor, image_id, image_tag, image_owner,
                  key_name, sec_groups, network_ids, config_drive_files,
                  user_data, port_ids, server_group_id, availability_zone)
        self.computeconfig[(name, amphora_flavor, image_id, image_tag,
                            image_owner, key_name, user_data,
                            server_group_id)] = (
            name, amphora_flavor,
            image_id, image_tag, image_owner, key_name, sec_groups,
            network_ids, config_drive_files, user_data, port_ids,
            server_group_id, 'build')
        compute_id = uuidutils.generate_uuid()

        adcinst = AdcaasDriver()
        adc_id = adcinst.create_adc()

        adc_proc = multiprocessing.Process(
            name='sdf', target=start_adcaas_work,
            args=(adc_id,), kwargs={})
        adc_proc.start()

        return adc_id

    def delete(self, compute_id):
        LOG.debug("Compute %s no-op, compute_id %s",
                  self.__class__.__name__, compute_id)
        self.computeconfig[compute_id] = (compute_id, 'delete')
        adcdriver = AdcaasDriver()
        adcdriver.delete_adc(compute_id)

    def status(self, compute_id):
        LOG.debug("Compute %s no-op, compute_id %s",
                  self.__class__.__name__, compute_id)
        self.computeconfig[compute_id] = (compute_id, 'status')

        adcinst = AdcaasDriver()

        status = adcinst.get_adc_status(compute_id)

        return constants.UP if status == "ACTIVE" else constants.DOWN


    def get_amphora(self, compute_id, management_network_id=None):
        LOG.debug("Compute %s no-op, compute_id %s, management_network_id %s",
                  self.__class__.__name__, compute_id, management_network_id)
        self.computeconfig[(compute_id, management_network_id)] = (
            compute_id, management_network_id, 'get_amphora')
        
        adcinst = AdcaasDriver()
        status = adcinst.get_adc_status(compute_id)
        (mgmt_ip, ext_ip) = adcinst.get_adc_ips(compute_id)

        if status != constants.ACTIVE:
            status = 'BUILDING'
        return data_models.Amphora(
            compute_id=compute_id,
            status=status,
            lb_network_ip=ext_ip
        ), None

    def create_server_group(self, name, policy):
        LOG.debug("Create Server Group %s no-op, name %s, policy %s ",
                  self.__class__.__name__, name, policy)
        self.computeconfig[(name, policy)] = (name, policy, 'create')

    def delete_server_group(self, server_group_id):
        LOG.debug("Delete Server Group %s no-op, id %s ",
                  self.__class__.__name__, server_group_id)
        self.computeconfig[server_group_id] = (server_group_id, 'delete')

    def attach_network_or_port(self, compute_id, network_id=None,
                               ip_address=None, port_id=None):
        LOG.debug("Compute %s no-op, attach_network_or_port compute_id %s,"
                  "network_id %s, ip_address %s, port_id %s",
                  self.__class__.__name__, compute_id,
                  network_id, ip_address, port_id)
        self.computeconfig[(compute_id, network_id, ip_address, port_id)] = (
            compute_id, network_id, ip_address, port_id,
            'attach_network_or_port')
        return network_models.Interface(
            id=uuidutils.generate_uuid(),
            compute_id=compute_id,
            network_id=network_id,
            fixed_ips=[],
            port_id=uuidutils.generate_uuid()
        )

    def detach_port(self, compute_id, port_id):
        LOG.debug("Compute %s no-op, detach_network compute_id %s, "
                  "port_id %s",
                  self.__class__.__name__, compute_id, port_id)
        self.computeconfig[(compute_id, port_id)] = (
            compute_id, port_id, 'detach_port')

    def validate_flavor(self, flavor_id):
        LOG.debug("Compute %s no-op, validate_flavor flavor_id %s",
                  self.__class__.__name__, flavor_id)
        self.computeconfig[flavor_id] = (flavor_id, 'validate_flavor')

    def validate_availability_zone(self, availability_zone):
        LOG.debug("Compute %s no-op, validate_availability_zone name %s",
                  self.__class__.__name__, availability_zone)
        self.computeconfig[availability_zone] = (
            availability_zone, 'validate_availability_zone')


class NoopComputeDriver(driver_base.ComputeBase):
    def __init__(self):
        super(NoopComputeDriver, self).__init__()
        self.driver = NoopManager()

    def build(self, name="amphora_name", amphora_flavor=None,
              image_id=None, image_tag=None, image_owner=None,
              key_name=None, sec_groups=None, network_ids=None,
              config_drive_files=None, user_data=None, port_ids=None,
              server_group_id=None, availability_zone=None):

        compute_id = self.driver.build(name, amphora_flavor,
                                       image_id, image_tag, image_owner,
                                       key_name, sec_groups, network_ids,
                                       config_drive_files, user_data, port_ids,
                                       server_group_id, availability_zone)
        return compute_id

    def delete(self, compute_id):
        self.driver.delete(compute_id)

    def status(self, compute_id):
        return self.driver.status(compute_id)

    def get_amphora(self, compute_id, management_network_id=None):
        return self.driver.get_amphora(compute_id, management_network_id)

    def create_server_group(self, name, policy):
        return self.driver.create_server_group(name, policy)

    def delete_server_group(self, server_group_id):
        self.driver.delete_server_group(server_group_id)

    def attach_network_or_port(self, compute_id, network_id=None,
                               ip_address=None, port_id=None):
        self.driver.attach_network_or_port(compute_id, network_id, ip_address,
                                           port_id)

    def detach_port(self, compute_id, port_id):
        self.driver.detach_port(compute_id, port_id)

    def validate_flavor(self, flavor_id):
        self.driver.validate_flavor(flavor_id)

    def validate_availability_zone(self, availability_zone):
        self.driver.validate_availability_zone(availability_zone)
