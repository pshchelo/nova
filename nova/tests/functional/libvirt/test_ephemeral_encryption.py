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

from unittest import mock

from castellan.common import exception as castellan_exception
from oslo_log import log as logging
from oslo_utils.fixture import uuidsentinel as uuids

import nova.conf
from nova import context as nova_context
from nova import crypto
from nova import objects
from nova.tests.functional.api import client as api_client
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

    def test_create_server_with_init_host_cleanup(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3)

        # There should be three libvirt secrets total currently.
        self.assertEqual(3, len(self.driver._host.list_all_secrets()))

        # Add a few fake unused secrets to test cleanup during init_host().
        self.driver._host.create_secret(
            'volume', 'fake1', password='pass1', uuid=uuids.fake1,
            description='Ephemeral encryption secret 1')
        self.driver._host.create_secret(
            'volume', 'fake2', password='pass2', uuid=uuids.fake2,
            description='Ephemeral encryption secret 2')
        # Make one secret for something other than ephemeral encryption. It
        # should not be cleaned up.
        self.driver._host.create_secret(
            'volume', 'fake3', password='pass3', uuid=uuids.fake3)

        # There should be six libvirt secrets total now.
        self.assertEqual(6, len(self.driver._host.list_all_secrets()))

        # And still three key manager secrets.
        self.assertEqual(3, len(self.key_mgr.list(self.context)))

        # Restart the compute host to make init_host() run.
        self.restart_compute_service('compute1')

        # There should only be four libvirt secrets after cleaning the unused
        # secrets (one of them is a secret unrelated to ephemeral encryption).
        self.assertEqual(4, len(self.driver._host.list_all_secrets()))

        # And the secrets for the server we have should still be present.
        self.assertSecretsMatch(server, 3)

        # The unrelated secret should also still be present.
        unrelated_secret = self.driver._host.find_secret('volume', 'fake3')
        self.assertEqual('fake3', unrelated_secret.usageID())

        # Now delete the server.
        self._delete_server(server)

        # Verify that secrets were deleted for each disk.
        self.assertSecretsDeleted(bdms)

    def test_create_server_without_key_access(self):
        # We will do the early API check for key access if we expect a fair
        # chance that a secret create would fail. The 'creator' role is the
        # default policy check in the key manager service when
        # enforce_scope=False. When enforce_scope=True, the 'creator' role is
        # not needed.
        self.flags(enforce_scope=False, group='oslo_policy')
        self.api.roles = ['member']

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        with mock.patch(
                'castellan.tests.unit.key_manager.mock_key_manager.'
                'MockKeyManager.store') as mock_store:
            # Simulate a key access permission error when checking in the API.
            mock_store.side_effect = castellan_exception.KeyManagerError(
                'Forbidden')
            # Create a server with ephemeral encryption.
            ex = self.assertRaises(
                api_client.OpenStackApiException,
                self._create_server_with_ephemeral_encryption_flavor)
            # The request should fail with a 403 error Forbidden.
            self.assertEqual(403, ex.response.status_code)
            self.assertRegex(
                ex.response.text,
                'Failed to create encryption secret.*Forbidden')

    def test_create_server_with_guest_launch_auto_heal_libvirt_secrets(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3)

        # There should be three libvirt secrets total currently.
        self.assertEqual(3, len(self.driver._host.list_all_secrets()))

        # Delete the libvirt secrets so we can test the auto healing.
        for bdm in bdms:
            secret_usage = f"{bdm.instance_uuid}_{bdm.uuid}"
            self.driver._host.delete_secret('volume', secret_usage)

        # Verify the libvirt secrets are gone.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

        # The key manager secrets should still be present.
        self.assertEqual(3, len(self.key_mgr.list(self.context)))

        # Try to hard reboot the server (this would normally fail if any
        # libvirt secret is missing).
        self._reboot_server(server, hard=True)

        # The libvirt secrets should have been recreated based on the key
        # manager secrets.
        self.assertSecretsMatch(server, 3)

        # Now delete the server.
        self._delete_server(server)

        # Verify that secrets were deleted for each disk.
        self.assertSecretsDeleted(bdms)
