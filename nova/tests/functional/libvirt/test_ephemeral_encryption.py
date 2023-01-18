# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging

import nova.conf
from nova import context as nova_context
from nova import crypto
from nova import objects
from nova.tests.functional.libvirt import base
from nova import utils

CONF = nova.conf.CONF
LOG = logging.getLogger(__name__)


class EphemeralEncryptionTestBase(base.ServersTestBase):

    CAST_AS_CALL = False

    def setUp(self):
        # Use a fake key manager service.
        self.flags(
            backend='castellan.tests.unit.key_manager.mock_key_manager.'
                'MockKeyManager', group='key_manager')
        super().setUp()
        self.context = nova_context.get_admin_context()
        self.key_mgr = crypto._get_key_manager()
        self.compute = self.start_compute()
        self.driver = self.computes[self.compute].driver
        self._run_periodics()

    def _create_server_with_ephemeral_encryption_flavor(self):
        extra_specs = {'hw:ephemeral_encryption': 'true'}
        flavor_id = self._create_flavor(
            disk=10, ephemeral=5, swap=128, extra_spec=extra_specs)
        server = self._create_server(flavor_id=flavor_id)
        return server

    def _get_key_mgr_secrets(self, ctx):
        # Return a dict of {uuid: secret}
        return {obj.id: obj.value for obj in self.key_mgr.list(ctx)}

    def assertSecretsMatch(self, server, num_expected):
        # Verify the expected number of secrets are in the key manager.
        keymgr_secrets = self._get_key_mgr_secrets(self.context)
        self.assertEqual(num_expected, len(keymgr_secrets))
        # Verify the expected number of BDMs.
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            self.context, server['id'])
        self.assertEqual(num_expected, len(bdms))
        # Verify that the BDM libvirt secrets match the secrets in the key
        # manager.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = self.driver._host.find_secret('volume', usage_id)
            self.assertEqual(
                s.value(), keymgr_secrets[bdm.encryption_secret_uuid])
        return bdms

    def assertSecretsDeleted(self, bdms):
        # Verify that libvirt secrets were deleted for each disk.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = self.driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # Verify that key manager secrets were deleted for each disk.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))


class EphemeralEncryptionTestCreate(EphemeralEncryptionTestBase):

    def test_create_server(self):
        # Verify we are reporting the correct traits.
        traits = self._get_provider_traits(self.compute_rp_uuids[self.compute])
        for trait in ('COMPUTE_EPHEMERAL_ENCRYPTION',
                      'COMPUTE_EPHEMERAL_ENCRYPTION_LUKS'):
            self.assertIn(trait, traits)

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3)

        # Now delete the server.
        self._delete_server(server)

        # Verify that secrets were deleted for each disk.
        self.assertSecretsDeleted(bdms)

    def test_create_server_with_local_delete(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3)

        # Force down nova-compute to cause a local delete.
        with utils.temporary_mutation(self.admin_api, microversion='2.11'):
            self.admin_api.force_down_service('compute1', 'nova-compute', True)

        # Delete the server.
        self._delete_server(server)

        # Verify that secrets were deleted from the key manager during local
        # delete. Libvirt secrets remain at this point because nova-compute has
        # not carried out the rest of the deletion yet.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = self.driver._host.find_secret('volume', usage_id)
            self.assertIsNotNone(s)

        # Run periodic task to complete deletions on nova-compute.
        self.computes[self.compute].manager._cleanup_running_deleted_instances(
            self.context)

        # Verify that all secrets including the libvirt secrets were deleted
        # for each disk.
        self.assertSecretsDeleted(bdms)
