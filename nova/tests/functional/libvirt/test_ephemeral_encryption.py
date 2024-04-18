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
import fixtures
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

    def _create_server_with_ephemeral_encryption_flavor(self, **kwargs):
        extra_specs = {'hw:ephemeral_encryption': 'true'}
        flavor_id = self._create_flavor(
            disk=10, ephemeral=5, swap=128, extra_spec=extra_specs)
        server = self._create_server(flavor_id=flavor_id, **kwargs)
        return server

    def _create_server_with_ephemeral_encryption_image(self, **kwargs):
        image_properties = {'hw_ephemeral_encryption': 'true'}
        image_id = self._create_image(image_properties)['id']
        flavor_id = self._create_flavor(disk=10, ephemeral=5, swap=128)
        server = self._create_server(
            image_uuid=image_id, flavor_id=flavor_id, **kwargs)
        return server

    def _get_key_mgr_secrets(self, ctx):
        # Return a dict of {uuid: secret}
        return {obj.id: obj.value for obj in self.key_mgr.list(ctx)}

    def assertLibvirtSecretsMatch(
            self, server, num_expected, driver, bdms=None):
        if bdms is None:
            bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                self.context, server['id'])
        keymgr_secrets = self._get_key_mgr_secrets(self.context)
        # Verify the expected number of BDMs.
        self.assertEqual(num_expected, len(bdms))
        # Verify that the BDM libvirt secrets match the secrets in the key
        # manager.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = driver._host.find_secret('volume', usage_id)
            self.assertEqual(
                s.value(), keymgr_secrets[bdm.encryption_secret_uuid])
        return bdms

    def assertSecretsMatch(self, server, num_expected, driver, bdms=None):
        # Verify the expected number of secrets are in the key manager.
        keymgr_secrets = self._get_key_mgr_secrets(self.context)
        self.assertEqual(num_expected, len(keymgr_secrets))
        return self.assertLibvirtSecretsMatch(
            server, num_expected, driver, bdms=bdms)

    def assertLibvirtSecretsDeleted(self, bdms, driver):
        # Verify that libvirt secrets were deleted for each disk.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

    def assertSecretsDeleted(self, bdms, driver):
        self.assertLibvirtSecretsDeleted(bdms, driver)
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
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Now delete the server.
        self._delete_server(server)

        # Verify that secrets were deleted for each disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_create_server_with_local_delete(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

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
        self.assertSecretsDeleted(bdms, self.driver)

    def test_create_server_with_init_host_cleanup(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

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
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # The unrelated secret should also still be present.
        unrelated_secret = self.driver._host.find_secret('volume', 'fake3')
        self.assertEqual('fake3', unrelated_secret.usageID())

        # Now delete the server.
        self._delete_server(server)

        # Verify that secrets were deleted for each disk.
        self.assertSecretsDeleted(bdms, self.driver)

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
        bdms = self.assertSecretsMatch(server, 3, self.driver)

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
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Now delete the server.
        self._delete_server(server)

        # Verify that secrets were deleted for each disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_create_server_with_encrypted_source_image(self):
        """Test that encryption is maintained by default.

        If the source image is encrypted and neither hw:ephemeral_encryption
        nor hw_ephemeral_encryption have been explicitly set, we should
        maintain encryption and create encrypted disks.
        """
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Simulate an encrypted image with secret ID in the image properties.
        # First create a secret for the image.
        secret_uuid = crypto.create_encryption_secret(
            self.context, 'foo', 'bar')
        image_properties = {
            'os_encrypt_key_id': secret_uuid,
            'os_encrypt_format': 'luks',
        }
        image_id = self._create_image(image_properties)['id']

        # Verify there is one secret in the key manager, for the image.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))
        # Verify there are no libvirt secrets yet.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

        # Create a server with the image and (hw:|hw_)ephemeral_encryption is
        # not set in the flavor or image.
        flavor_id = self._create_flavor(disk=10, ephemeral=0, swap=0)
        server = self._create_server(flavor_id=flavor_id, image_uuid=image_id)

        # We should have created one libvirt secret for the server disk.
        self.assertLibvirtSecretsMatch(server, 1, self.driver)

        # Now delete the server.
        self._delete_server(server)

        # We should have deleted the server disk libvirt secret.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

        # The one secret for the encrypted image should still be in the key
        # manager.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))

    def test_create_server_with_encrypted_source_image_flavor_disabled(self):
        """Test that the source image will be decrypted if specified.

        If the source image is encrypted and either hw:ephemeral_encryption
        or hw_ephemeral_encryption have been explicitly set to false, we should
        create unencrypted disks.

        NOTE: This currently will NOT work in real life because of image cache
        fingerprint collision.
        """
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Simulate an encrypted image with secret ID in the image properties.
        # First create a secret for the image.
        secret_uuid = crypto.create_encryption_secret(
            self.context, 'foo', 'bar')
        image_properties = {
            'os_encrypt_key_id': secret_uuid,
            'os_encrypt_format': 'luks',
        }
        image_id = self._create_image(image_properties)['id']

        # Verify there is one secret in the key manager, for the image.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))
        # Verify there are no libvirt secrets.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

        # Create a server with the image and hw:ephemeral_encryption = false.
        flavor_id = self._create_flavor(
            disk=10, ephemeral=0, swap=0,
            extra_spec={'hw:ephemeral_encryption': 'false'})
        server = self._create_server(flavor_id=flavor_id, image_uuid=image_id)

        # There should still be no libvirt secrets.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))
        # There should still be one secret in the key manager, for the image.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))

        # Now delete the server.
        self._delete_server(server)

        # The one secret for the encrypted image should still be in the key
        # manager.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))

    def test_create_server_with_encrypted_source_image_also_disabled(self):
        """Test that the source image will be decrypted if specified.

        If the source image is encrypted and either hw:ephemeral_encryption
        or hw_ephemeral_encryption have been explicitly set to false, we should
        create unencrypted disks.

        NOTE: This currently will NOT work in real life because of image cache
        fingerprint collision.
        """
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Simulate an encrypted image with secret ID in the image properties.
        # First create a secret for the image.
        secret_uuid = crypto.create_encryption_secret(
            self.context, 'foo', 'bar')
        # The image properties will also request unencrypted disks.
        image_properties = {
            'os_encrypt_key_id': secret_uuid,
            'os_encrypt_format': 'luks',
            'hw_ephemeral_encryption': 'false',
        }
        image_id = self._create_image(image_properties)['id']

        # Verify there is one secret in the key manager, for the image.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))
        # Verify there are no libvirt secrets.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

        # Create a server with the image.
        flavor_id = self._create_flavor(disk=10, ephemeral=0, swap=0)
        server = self._create_server(flavor_id=flavor_id, image_uuid=image_id)

        # There should still be no libvirt secrets.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))
        # There should still be one secret in the key manager, for the image.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))

        # Now delete the server.
        self._delete_server(server)

        # The one secret for the encrypted image should still be in the key
        # manager.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))


class EphemeralEncryptionTestResize(EphemeralEncryptionTestBase):

    def setUp(self):
        super().setUp()
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver._get_instance_disk_info'))
        self.useFixture(fixtures.MockPatch('os.rename'))
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.delete_instance_files'))

    def test_resize_server_same_host(self):
        self.skipTest("Fix later")  # FIXME(pas-ha):
        self.flags(allow_resize_to_same_host=True)

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Make note of the original flavor and create a new flavor.
        server_details = self._show_server(server)
        orig_flavor_id = server_details['flavor']['id']
        extra_specs = {'hw:ephemeral_encryption': 'true'}
        new_flavor_id = self._create_flavor(extra_spec=extra_specs)

        # Resize the server to the new flavor.
        self._resize_server(server, new_flavor_id)

        # Assert the server now has the new flavor.
        server_details = self._show_server(server)
        self.assertEqual(new_flavor_id, server_details['flavor']['id'])

        # We should still have three key manager secrets and three libvirt
        # secrets and they should be the same ones from earlier.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Revert the resize.
        self._revert_resize(server)

        # Assert the server is back to the original flavor.
        server_details = self._show_server(server)
        self.assertEqual(orig_flavor_id, server_details['flavor']['id'])

        # Resize the server again.
        self._resize_server(server, new_flavor_id)

        # Assert the server now has the new flavor.
        server_details = self._show_server(server)
        self.assertEqual(new_flavor_id, server_details['flavor']['id'])

        # Confirm the resize.
        self._confirm_resize(server)

        # Assert the server still has the new flavor.
        server_details = self._show_server(server)
        self.assertEqual(new_flavor_id, server_details['flavor']['id'])

        # We should still have three key manager secrets and three libvirt
        # secrets and they should be the same ones from earlier.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Delete the server.
        self._delete_server(server)

        # Verify that secrets were deleted for each disk.
        # FIXME(pas-ha): swap secret is not deleted
        self.assertSecretsDeleted(bdms, self.driver)

    def test_resize_server_different_host(self, is_resize=True):
        self.skipTest("Fix later")  # FIXME(pas-ha):
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.'
            'check_instance_shared_storage_remote', return_value=False))

        self.start_compute(hostname='compute2')
        self._run_periodics()

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()
        src_host = self._show_server(
            server, api=self.admin_api)['OS-EXT-SRV-ATTR:host']

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        src_driver = self.computes[src_host].driver
        bdms = self.assertSecretsMatch(server, 3, src_driver)

        if is_resize:
            # Make note of the original flavor and create a new flavor.
            server_details = self._show_server(server)
            orig_flavor_id = server_details['flavor']['id']
            extra_specs = {'hw:ephemeral_encryption': 'true'}
            new_flavor_id = self._create_flavor(extra_spec=extra_specs)

            # Resize the server to the new flavor.
            self._resize_server(server, new_flavor_id)
        else:
            # Cold migrate the server.
            self._migrate_server(server)

        # Assert that it moved.
        dest_host = self._show_server(
            server, api=self.admin_api)['OS-EXT-SRV-ATTR:host']
        self.assertNotEqual(src_host, dest_host)

        if is_resize:
            # Assert the server now has the new flavor.
            server_details = self._show_server(server)
            self.assertEqual(new_flavor_id, server_details['flavor']['id'])

        # The libvirt secrets should be on the destination now and we should
        # still have the key manager secrets matching.
        dest_driver = self.computes[dest_host].driver
        # FIXME(pas-ha): fails to find secret for swap
        self.assertSecretsMatch(server, 3, dest_driver, bdms=bdms)
        # The secrets should still be on the source too, along with the disks.
        self.assertSecretsMatch(server, 3, src_driver, bdms=bdms)

        # Revert the resize or migration.
        self._revert_resize(server)

        # Assert that it moved back.
        self.assertEqual(
            src_host,
            self._show_server(
                server, api=self.admin_api)['OS-EXT-SRV-ATTR:host'])

        if is_resize:
            # Assert the server is back to the original flavor.
            server_details = self._show_server(server)
            self.assertEqual(orig_flavor_id, server_details['flavor']['id'])

        # Assert that the libvirt secrets have been removed from the
        # destination.
        self.assertLibvirtSecretsDeleted(bdms, dest_driver)

        # The libvirt secrets should be on the source now and we should
        # still have the key manager secrets matching.
        # FIXME(pas-ha): secret is None
        self.assertSecretsMatch(server, 3, src_driver)

        # Resize or migrate the server again.
        if is_resize:
            self._resize_server(server, new_flavor_id)
        else:
            self._migrate_server(server)

        # Assert that it moved.
        self.assertEqual(
            dest_host,
            self._show_server(
                server, api=self.admin_api)['OS-EXT-SRV-ATTR:host'])

        if is_resize:
            # Assert the server now has the new flavor.
            server_details = self._show_server(server)
            self.assertEqual(new_flavor_id, server_details['flavor']['id'])

        # The libvirt secrets should be on the destination now and we should
        # still have the key manager secrets matching.
        self.assertSecretsMatch(server, 3, dest_driver)
        # The secrets should still be on the source too, along with the disks.
        self.assertSecretsMatch(server, 3, src_driver, bdms=bdms)

        # Confirm the migration.
        self._confirm_resize(server)

        if is_resize:
            # Assert the server still has the new flavor.
            server_details = self._show_server(server)
            self.assertEqual(new_flavor_id, server_details['flavor']['id'])

        # Assert that the libvirt secrets have been removed from the source.
        self.assertLibvirtSecretsDeleted(bdms, src_driver)

        # The libvirt secrets should still be on the destination and we should
        # still have the key manager secrets matching.
        self.assertSecretsMatch(server, 3, dest_driver)

        # Delete the server.
        self._delete_server(server)

        # Verify that there are no libvirt secrets on either host.
        self.assertSecretsDeleted(bdms, src_driver)
        self.assertSecretsDeleted(bdms, dest_driver)

    def test_cold_migrate_server(self):
        # We need the admin API for cold migration.
        self.api = self.admin_api
        self.test_resize_server_different_host(is_resize=False)


class EphemeralEncryptionLiveMigrateBase(
    # This has to go before EphemeralEncryptionTestBase so that it patches the
    # LibvirtFixture before useFixture(LibvirtFixture) happens.
    base.LibvirtMigrationMixin,
    EphemeralEncryptionTestBase,
):
    # Some live migration auto-configuration was added in later microversions.
    microversion = 'latest'
    ADMIN_API = True

    def setUp(self):
        super().setUp()
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver._get_instance_disk_info'))
        self.useFixture(fixtures.MockPatch('os.rename'))
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.'
            'check_instance_shared_storage_remote', return_value=False))
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.'
            '_check_shared_storage_test_file', return_value=False))
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.delete_instance_files'))

        self.start_compute(hostname='compute2')
        self._run_periodics()


class EphemeralEncryptionLiveMigrate(EphemeralEncryptionLiveMigrateBase):

    def test_live_migrate_server(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor(
            networks='none')
        src_host = self._show_server(server)['OS-EXT-SRV-ATTR:host']

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        src_driver = self.computes[src_host].driver
        bdms = self.assertSecretsMatch(server, 3, src_driver)

        # Set stuff LibvirtMigrationMixin needs in order to work.
        self.server = server
        self.src = self.computes[src_host]
        self.dest = [v for k, v in self.computes.items() if k != src_host][0]

        # Live migrate the server.
        self._live_migrate_server(server)
        dest_host = self._show_server(server)['OS-EXT-SRV-ATTR:host']

        # Assert that it moved.
        self.assertNotEqual(src_host, dest_host)

        # Assert that the libvirt secrets have been removed from the source.
        self.assertLibvirtSecretsDeleted(bdms, src_driver)

        # The libvirt secrets should be on the destination now and we should
        # still have the key manager secrets matching.
        dest_driver = self.computes[dest_host].driver
        self.assertSecretsMatch(server, 3, dest_driver, bdms=bdms)

        # Delete the server.
        self._delete_server(server)

        # Verify that there are no libvirt secrets on either host.
        self.assertSecretsDeleted(bdms, src_driver)
        self.assertSecretsDeleted(bdms, dest_driver)


class EphemeralEncryptionLiveMigrateFail(EphemeralEncryptionLiveMigrateBase):

    def _migrate_stub(self, domain, destination, params, flags):
        # Make the live migration fail.
        conn = self.src.driver._host.get_connection()
        dom = conn.lookupByUUIDString(self.server['id'])
        dom.fail_job()
        self.migrate_stub_ran = True

    def test_rollback_live_migration(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor(
            networks='none')
        src_host = self._show_server(server)['OS-EXT-SRV-ATTR:host']

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        src_driver = self.computes[src_host].driver
        bdms = self.assertSecretsMatch(server, 3, src_driver)

        # Set stuff LibvirtMigrationMixin needs in order to work.
        self.server = server
        self.src = self.computes[src_host]
        self.dest = [v for k, v in self.computes.items() if k != src_host][0]

        # Live migrate the server.
        self._live_migrate_server(server, migration_expected_state='failed')

        # Assert that it didn't move.
        self.assertEqual(
            src_host, self._show_server(server)['OS-EXT-SRV-ATTR:host'])

        # Assert that the libvirt secrets have been removed from the
        # destination.
        dest_driver = self.dest.driver
        self.assertLibvirtSecretsDeleted(bdms, dest_driver)

        # The libvirt secrets should be on the source now and we should
        # still have the key manager secrets matching.
        self.assertSecretsMatch(server, 3, src_driver, bdms=bdms)

        # Delete the server.
        self._delete_server(server)

        # Verify that there are no libvirt secrets on either host.
        self.assertSecretsDeleted(bdms, src_driver)
        self.assertSecretsDeleted(bdms, dest_driver)


class EphemeralEncryptionTestRebuild(EphemeralEncryptionTestBase):

    def test_rebuild_server_encryption_from_flavor_same_image(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Rebuild the server without changing the image.
        image_id = self._show_server(server)['image']['id']
        self._rebuild_server(server, image_id)

        # The image should not have changed.
        image_id_after_rebuild = self._show_server(server)['image']['id']
        self.assertEqual(image_id, image_id_after_rebuild)

        # We should still have three key manager secrets and three libvirt
        # secrets and they should be the same ones from earlier.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Now delete the server.
        self._delete_server(server)

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_rebuild_server_encryption_from_flavor_new_image_encrypt(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # Rebuild the server with a new image requesting encryption.
        image = self._create_image({'hw_ephemeral_encryption': 'true'})
        self._rebuild_server(server, image['id'])

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # The image should have changed.
        image_id_after_rebuild = self._show_server(server)['image']['id']
        self.assertEqual(image['id'], image_id_after_rebuild)

        # We should still have three key manager secrets and three libvirt
        # secrets and they should be the same ones from earlier.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Now delete the server.
        self._delete_server(server)

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_rebuild_server_encryption_from_flavor_new_image_no_encrypt(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Rebuild the server with a new image not requesting encryption.
        image = self._create_image({})
        self._rebuild_server(server, image['id'])

        # The image should have changed.
        image_id_after_rebuild = self._show_server(server)['image']['id']
        self.assertEqual(image['id'], image_id_after_rebuild)

        # We should still have three key manager secrets and three libvirt
        # secrets and they should be the same ones from earlier.
        # Even though the image didn't request encryption, we still have
        # encryption specified in the flavor.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Now delete the server.
        self._delete_server(server)

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_rebuild_server_encryption_from_image_same_image(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_image()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Rebuild the server without changing the image.
        image_id = self._show_server(server)['image']['id']
        self._rebuild_server(server, image_id)

        # The image should not have changed.
        image_id_after_rebuild = self._show_server(server)['image']['id']
        self.assertEqual(image_id, image_id_after_rebuild)

        # We should still have three key manager secrets and three libvirt
        # secrets and they should be the same ones from earlier.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Now delete the server.
        self._delete_server(server)

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_rebuild_server_encryption_from_image_new_image_encrypt(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_image()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Rebuild the server with a new image requesting encryption.
        image = self._create_image({'hw_ephemeral_encryption': 'true'})
        self._rebuild_server(server, image['id'])

        # The image should have changed.
        image_id_after_rebuild = self._show_server(server)['image']['id']
        self.assertEqual(image['id'], image_id_after_rebuild)

        # We should still have three key manager secrets and three libvirt
        # secrets and they should be the same ones from earlier.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Now delete the server.
        self._delete_server(server)

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_rebuild_server_encryption_from_image_new_image_no_encrypt(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_image()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Rebuild the server with a new image not requesting encryption.
        image = self._create_image({})
        self._rebuild_server(server, image['id'])

        # The image should have changed.
        image_id_after_rebuild = self._show_server(server)['image']['id']
        self.assertEqual(image['id'], image_id_after_rebuild)

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

        # Now delete the server.
        self._delete_server(server)

    def test_rebuild_server_no_initial_encryption(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server without ephemeral encryption.
        flavor_id = self._create_flavor(disk=10, ephemeral=5, swap=128)
        server = self._create_server(flavor_id=flavor_id)

        # Verify there are still no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # The flavor we created has ephemeral=5 and swap=128, so we will have
        # three disks, the root disk, an ephemeral disk, and a swap disk.
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            self.context, server['id'])
        self.assertEqual(3, len(bdms))

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

        # Rebuild the server with a new image requesting encryption.
        image = self._create_image({'hw_ephemeral_encryption': 'true'})
        self._rebuild_server(server, image['id'])

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Now delete the server.
        self._delete_server(server)

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_rebuild_server_encryption_change_rejected_non_to_encrypt(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server without ephemeral encryption.
        flavor_id = self._create_flavor(disk=10, ephemeral=5, swap=128)
        server = self._create_server(flavor_id=flavor_id)

        # Verify there are still no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # The flavor we created has ephemeral=5 and swap=128, so we will have
        # three disks, the root disk, an ephemeral disk, and a swap disk.
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            self.context, server['id'])
        self.assertEqual(3, len(bdms))

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

        # Attempt to rebuild the server with a new image requesting encryption
        # as a different user (admin). This should be rejected.
        image = self._create_image({'hw_ephemeral_encryption': 'true'})
        ex = self.assertRaises(
            api_client.OpenStackApiException, self._rebuild_server, server,
            image['id'], api=self.admin_api)
        self.assertEqual(403, ex.response.status_code)
        msg = (
            'Only the user_id that owns the instance may change from '
            'ephemeral encryption to no ephemeral encryption or vice versa.')
        self.assertIn(msg, ex.response.text)

        # Delete that server.
        self._delete_server(server)

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_rebuild_server_encryption_change_rejected_encrypt_to_non(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_image()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Attempt to rebuild the server with a new image without ephemeral
        # encryption as a different user (admin). This should be rejected.
        image = self._create_image({})
        ex = self.assertRaises(
            api_client.OpenStackApiException, self._rebuild_server, server,
            image['id'], api=self.admin_api)
        self.assertEqual(403, ex.response.status_code)
        msg = (
            'Only the user_id that owns the instance may change from '
            'ephemeral encryption to no ephemeral encryption or vice versa.')
        self.assertIn(msg, ex.response.text)

        # Now delete the server.
        self._delete_server(server)

        # Verify that libvirt and key manager secrets were deleted for each
        # disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_evacuate_server(self):
        self.useFixture(fixtures.MockPatch(
            'nova.compute.manager.ComputeManager.'
            '_is_instance_storage_shared', return_value=False))

        self.start_compute(hostname='compute2')
        self._run_periodics()

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()
        src_host = self._show_server(
            server, api=self.admin_api)['OS-EXT-SRV-ATTR:host']

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        src_driver = self.computes[src_host].driver
        bdms = self.assertSecretsMatch(server, 3, src_driver)

        # Stop the server, stop and force down the source compute service, and
        # evacuate the server.
        self._stop_server(server)
        self.computes[src_host].stop()
        with utils.temporary_mutation(self.admin_api, microversion='2.14'):
            self.admin_api.force_down_service(src_host, 'nova-compute', True)
            self._evacuate_server(server)

        dest_host = self._show_server(
            server, api=self.admin_api)['OS-EXT-SRV-ATTR:host']

        # Assert that it moved.
        self.assertNotEqual(src_host, dest_host)

        # Start the compute service again to cleanup evacuated instance
        # artifacts.
        self.computes[src_host].start()

        # Assert that the libvirt secrets have been removed from the source.
        self.assertLibvirtSecretsDeleted(bdms, src_driver)

        # The libvirt secrets should be on the destination now and we should
        # still have the key manager secrets matching.
        dest_driver = self.computes[dest_host].driver
        self.assertSecretsMatch(server, 3, dest_driver, bdms=bdms)

        # Delete the server.
        self._delete_server(server)

        # Verify that there are no libvirt secrets on either host and there are
        # no secrets in the key manager.
        self.assertSecretsDeleted(bdms, src_driver)
        self.assertSecretsDeleted(bdms, dest_driver)
