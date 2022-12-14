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

import io
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

    def restart_compute_service(
        self,
        hostname,
        host_info=None,
        pci_info=None,
        mdev_info=None,
        vdpa_info=None,
        libvirt_version=None,
        qemu_version=None,
        keep_hypervisor_state=True,
    ):
        """Refresh self.driver reference after compute service restart.

        We need to refresh our self.driver reference if there is a compute
        restart because self.start_compute will replace self.computes[hostname]
        with a new object.
        """
        compute = super().restart_compute_service(
            hostname, host_info=host_info, pci_info=pci_info,
            mdev_info=mdev_info, vdpa_info=vdpa_info,
            libvirt_version=libvirt_version, qemu_version=qemu_version,
            keep_hypervisor_state=keep_hypervisor_state)
        self.driver = compute.driver
        return compute

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


class EphemeralEncryptionTestRescue(EphemeralEncryptionTestBase):

    def setUp(self):
        super().setUp()
        self.unrescue_file = io.StringIO()
        self.mock_file = mock.mock_open()
        self.mock_file.return_value.write.side_effect = self._fake_write
        self.mock_file.return_value.read.side_effect = self._fake_read
        self.useFixture(fixtures.MockPatch('builtins.open', self.mock_file))
        self.useFixture(fixtures.MockPatch('os.unlink'))

    def _fake_write(self, s):
        self.unrescue_file.write(s)

    def _fake_read(self):
        return self.unrescue_file.getvalue()

    def test_rescue_server(self, rescue_image_id=None):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Rescue the server.
        self._rescue_server(server, image_uuid=rescue_image_id)

        # We should still have the same secrets as before the rescue.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Unrescue the server.
        self._unrescue_server(server)

        # We should still have the same secrets as before the rescue.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Now delete the server.
        self._delete_server(server)

        # Verify that libvirt secrets were deleted for each disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_rescue_server_with_image(self):
        self.test_rescue_server(
            rescue_image_id='70a599e0-31e7-49b7-b260-868f441e862b')

    def test_rescue_server_with_config_option(self):
        self.flags(
            rescue_image_id='70a599e0-31e7-49b7-b260-868f441e862b',
            group='libvirt')
        self.test_rescue_server()

    def test_stable_rescue_server(self):
        image_properties = {
            'hw_rescue_device': 'disk',
            'hw_rescue_bus': 'virtio',
        }
        image_id = self._create_image(image_properties)['id']
        self.test_rescue_server(rescue_image_id=image_id)

    def test_rescue_server_with_encrypted_image(self):
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
        # Create a server that does not have encrypted disks other than the
        # rescue disk which will be created from the encrypted rescue image.
        server = self._create_server()

        # Verify there is one secret in the key manager, for the image.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))
        # Verify there are no libvirt secrets yet.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

        # Rescue the server.
        self._rescue_server(server, image_uuid=image_id)

        # We should have created one libvirt secret for the rescue disk.
        s = self.driver._host.find_secret(
            'volume', f'{server["id"]}_rescue_disk')
        self.assertEqual('foo', s.value())

        # Unrescue the server.
        self._unrescue_server(server)

        # We should have deleted the rescue disk libvirt secret.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

        # Now delete the server.
        self._delete_server(server)

        # The one secret for the encrypted image should still be in the key
        # manager.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))

    def test_rescue_server_with_encrypted_image_and_disks(self):
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

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three libvirt secrets: one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertLibvirtSecretsMatch(server, 3, self.driver)

        # Rescue the server.
        self._rescue_server(server, image_uuid=image_id)

        # There should be one additional libvirt secret that was created for
        # the rescue disk.
        self.assertEqual(4, len(self.driver._host.list_all_secrets()))
        s = self.driver._host.find_secret(
            'volume', f'{server["id"]}_rescue_disk')
        self.assertEqual('foo', s.value())
        # We should still have the same secrets as before the rescue for the
        # other disks.
        self.assertLibvirtSecretsMatch(server, 3, self.driver, bdms=bdms)

        # Unrescue the server.
        self._unrescue_server(server)

        # We should have deleted the rescue disk libvirt secret.
        self.assertEqual(3, len(self.driver._host.list_all_secrets()))
        self.assertIsNone(self.driver._host.find_secret(
            'volume', f'{server["id"]}_rescue_disk'))

        # Now delete the server.
        self._delete_server(server)

        # The one secret for the encrypted image should still be in the key
        # manager.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))

        # There should be no libvirt secrets.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

    def test_rescue_server_with_init_host_cleanup(self):
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
        # Create a server that does not have encrypted disks other than the
        # rescue disk which will be created from the encrypted rescue image.
        server = self._create_server()

        # Verify there is one secret in the key manager, for the image.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))
        # Verify there are no libvirt secrets yet.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

        # Rescue the server.
        self._rescue_server(server, image_uuid=image_id)

        # We should have created one libvirt secret for the rescue disk.
        s = self.driver._host.find_secret(
            'volume', f'{server["id"]}_rescue_disk')
        self.assertEqual('foo', s.value())

        # Create a fake unused libvirt secret to test cleanup during
        # init_host().
        self.driver._host.create_secret(
            'volume', f'{uuids.old_instance}_rescue_disk', password='pass',
            uuid=uuids.unused_secret, description='Ephemeral '
            f'encryption secret for instance {uuids.old_instance} rescue disk')

        # There should be two libvirt secrets total now.
        self.assertEqual(2, len(self.driver._host.list_all_secrets()))

        # Restart the compute host to make init_host() run.
        self.restart_compute_service('compute1')

        # There should be only one libvirt secret now.
        self.assertEqual(1, len(self.driver._host.list_all_secrets()))

        # And it should be for the instance running on this host.
        s = self.driver._host.find_secret(
            'volume', f'{server["id"]}_rescue_disk')
        self.assertEqual('foo', s.value())

        # Unrescue the server.
        self._unrescue_server(server)

        # We should have deleted the rescue disk libvirt secret.
        self.assertEqual(0, len(self.driver._host.list_all_secrets()))

        # Now delete the server.
        self._delete_server(server)

        # The one secret for the encrypted image should still be in the key
        # manager.
        self.assertEqual(1, len(self.key_mgr.list(self.context)))

    def test_rescue_server_with_encrypted_image_missing_secret(self):
        # Simulate an encrypted image with secret ID in the image properties.
        image_properties = {
            'os_encrypt_key_id': uuids.secret,
            'os_encrypt_format': 'luks',
        }
        image_id = self._create_image(image_properties)['id']

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        # (Note that there is no secret for the image because we didn't create
        # one).
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Rescue the server (normally the expected state is 'RESCUE' but we
        # expect this to fail due to the missing secret).
        self._rescue_server(
            server, image_uuid=image_id, expected_state='ACTIVE')
        self._wait_for_action_fail_completion(
            server, 'rescue', 'compute_rescue_instance')

        # Verify that the rescue instance action shows an error.
        actions = objects.InstanceActionList.get_by_instance_uuid(
            self.context, server['id'])
        rescue_action = None
        for action in actions:
            if action.action == 'rescue':
                rescue_action = action
                break
        self.assertEqual('Error', rescue_action.message)

        # Verify that the instance action event for the rescue shows a result
        # of error and the expected message in the details.
        events = objects.InstanceActionEventList.get_by_action(
            self.context, rescue_action.id)
        self.assertIn(
            f'Failed to find encryption secret {uuids.secret} in the key '
            f'manager for rescue image {image_id}',
            events[0].details)
        self.assertEqual('Error', events[0].result)

        # Verify the server is still in ACTIVE state and we didn't put it into
        # ERROR.
        server = self._show_server(server)
        self.assertEqual('ACTIVE', server['status'])

        # We should still have three key manager secrets and three libvirt
        # secrets and they should be the same ones from earlier.
        self.assertSecretsMatch(server, 3, self.driver, bdms=bdms)


class EphemeralEncryptionTestSnapshot(EphemeralEncryptionTestBase):

    def setUp(self):
        super().setUp()
        self.useFixture(
            fixtures.MockPatch('nova.virt.libvirt.utils.get_disk_size'))
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.utils.get_disk_backing_file'))
        self.useFixture(fixtures.MockPatch('nova.virt.images.qemu_img_info'))
        self.useFixture(
            fixtures.MockPatch('nova.virt.libvirt.utils.create_image'))
        self.useFixture(fixtures.MockPatch('nova.privsep.path.chown'))
        self.useFixture(
            fixtures.MockPatch('nova.virt.images.convert_image'))

    def _test_snapshot_server(self, cold_snapshot=False):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server1 = self._create_server_with_ephemeral_encryption_flavor()

        if cold_snapshot:
            self._stop_server(server1)

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms1 = self.assertSecretsMatch(server1, 3, self.driver)

        # Snapshot the server.
        with utils.temporary_mutation(self.api, microversion='2.45'):
            image_id = self._snapshot_server(
                server1, 'cool_snapshot')['image_id']
        self._wait_for_instance_action_event(
            server1, 'createImage', 'compute_snapshot_instance', 'Success')

        # We should have an additional secret created for the snapshot image.
        self.assertEqual(4, len(self._get_key_mgr_secrets(self.context)))

        # We should still have the same libvirt secrets for the disks.
        self.assertLibvirtSecretsMatch(server1, 3, self.driver, bdms=bdms1)

        # Create a new server from the snapshot we created.
        server2 = self._create_server_with_ephemeral_encryption_flavor(
            image_uuid=image_id)

        # There should be 8 secrets in the key manager now: three for server1
        # BDMs, one for the snapshot image, three for server2 BDMs and one for
        # the server2 root disk BDM backing image secret.
        self.assertEqual(8, len(self._get_key_mgr_secrets(self.context)))

        # There should be three secrets in libvirt for server2, one for the
        # root disk, one for the ephemeral disk, and one for the swap disk.
        bdms2 = self.assertLibvirtSecretsMatch(server2, 3, self.driver)

        # Delete the first server.
        self._delete_server(server1)

        # Libvirt secrets for server1 should have been deleted.
        self.assertLibvirtSecretsDeleted(bdms1, self.driver)

        # There should be four secrets in the key manager left for server2
        # (three BDMs and one backing file secret for the root disk BDM) and
        # one secret for the snapshot image.
        self.assertEqual(5, len(self._get_key_mgr_secrets(self.context)))

        # Libvirt secrets for server2 should still be there.
        self.assertLibvirtSecretsMatch(server2, 3, self.driver, bdms=bdms2)

        # Delete the second server.
        self._delete_server(server2)

        # Libvirt secrets for server2 should have been deleted.
        self.assertLibvirtSecretsDeleted(bdms2, self.driver)

        # There should be one secret left in the key manager for the snapshot
        # image. This secret will not be deleted by Nova because it's a secret
        # for an image in Glance. Deletion of the Glance image and secret must
        # be done manually if/when deletion of the Glance image is desired.
        self.assertEqual(1, len(self._get_key_mgr_secrets(self.context)))

    def test_live_snapshot_server(self):
        self._test_snapshot_server()

    def test_cold_snapshot_server(self):
        self._test_snapshot_server(cold_snapshot=True)

    def test_shelve_server(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Shelve offload the server.
        self._shelve_server(server)

        # We should not have created an additional secret for the shelved
        # snapshot image because secrets are reused for the shelve action.
        self.assertEqual(3, len(self._get_key_mgr_secrets(self.context)))

        # The libvirt secrets should have been deleted when the server was
        # shelve offloaded.
        self.assertLibvirtSecretsDeleted(bdms, self.driver)

        # Unshelve the server.
        self._unshelve_server(server)

        # The libvirt secrets should have been created upon unshelving.
        self.assertSecretsMatch(server, 3, self.driver)

        # Delete the server.
        self._delete_server(server)

        # Verify that libvirt secrets were deleted for each disk.
        self.assertSecretsDeleted(bdms, self.driver)

    def test_shelve_and_delete_server(self):
        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(self.context)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        bdms = self.assertSecretsMatch(server, 3, self.driver)

        # Shelve offload the server.
        self._shelve_server(server)

        # We should not have created an additional secret for the shelved
        # snapshot image because secrets are reused for the shelve action.
        self.assertEqual(3, len(self._get_key_mgr_secrets(self.context)))

        # The libvirt secrets should have been deleted when the server was
        # shelve offloaded.
        self.assertLibvirtSecretsDeleted(bdms, self.driver)

        # Delete the server.
        self._delete_server(server)

        # Verify that key manager secrets were deleted for each disk.
        self.assertSecretsDeleted(bdms, self.driver)
