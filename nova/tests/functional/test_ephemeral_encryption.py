#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_utils.fixture import uuidsentinel

from nova import context
from nova import objects
from nova.tests.functional.api import client as api_client
from nova.tests.functional import integrated_helpers


class _TestEphemeralEncryptionBase(
    integrated_helpers.ProviderUsageBaseTestCase
):
    # NOTE(lyarwood): A dict of test flavors defined per test class,
    # keyed by flavor name and providing an additional dict containing an 'id'
    # and optional 'extra_specs' dict. For example:
    #   {
    #       'name': {
    #           'id': uuidsentinel.flavor_id
    #           'extra_specs': {
    #               'hw:foo': 'bar'
    #           }
    #       }
    #   }
    flavors = {}

    def setUp(self):
        super().setUp()
        # Use a fake key manager service.
        self.flags(
            backend='castellan.tests.unit.key_manager.mock_key_manager.'
                'MockKeyManager', group='key_manager')

        self.ctxt = context.get_admin_context()

        # Create the required test flavors
        for name, details in self.flavors.items():
            flavor = self.admin_api.post_flavor({
                'flavor': {
                    'name': name,
                    'id': details['id'],
                    'ram': 512,
                    'vcpus': 1,
                    'disk': 1024,
                }
            })
            # Add the optional extra_specs
            if details.get('extra_specs'):
                self.admin_api.post_extra_spec(
                    flavor['id'], {'extra_specs': details['extra_specs']})

        # We only need a single compute for these tests
        self._start_compute(host='compute1')

    def _assert_ephemeral_encryption_enabled(self, server_id):
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            self.ctxt, server_id)
        for bdm in bdms:
            if bdm.is_local:
                self.assertTrue(bdm.encrypted)

    def _assert_ephemeral_encryption_disabled(self, server_id):
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            self.ctxt, server_id)
        for bdm in bdms:
            if bdm.is_local:
                self.assertFalse(bdm.encrypted)


class TestEphemeralEncryptionAvailable(_TestEphemeralEncryptionBase):

    compute_driver = 'fake.EphEncryptionDriver'
    flavors = {
        'no_eph_encryption': {
            'id': uuidsentinel.no_eph_encryption
        },
        'eph_encryption': {
            'id': uuidsentinel.eph_encryption_flavor,
            'extra_specs': {
                'hw:ephemeral_encryption': 'True'
            }
        },
        'eph_encryption_disabled': {
            'id': uuidsentinel.eph_encryption_disabled_flavor,
            'extra_specs': {
                'hw:ephemeral_encryption': 'False'
            }
        },
    }

    def test_image_requested(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.no_eph_encryption,
            image_uuid=uuidsentinel.eph_encryption,
            networks=[])
        server_id = self._assert_build_request_success(server_request)
        self._assert_ephemeral_encryption_enabled(server_id)

    def test_image_disabled(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.no_eph_encryption,
            image_uuid=uuidsentinel.eph_encryption_disabled,
            networks=[])
        server_id = self._assert_build_request_success(server_request)
        self._assert_ephemeral_encryption_disabled(server_id)

    def test_flavor_requested(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.eph_encryption_flavor,
            networks=[])
        server_id = self._assert_build_request_success(server_request)
        self._assert_ephemeral_encryption_enabled(server_id)

    def test_flavor_disabled(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.eph_encryption_disabled_flavor,
            networks=[])
        server_id = self._assert_build_request_success(server_request)
        self._assert_ephemeral_encryption_disabled(server_id)

    def test_flavor_and_image_requested(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.eph_encryption_flavor,
            image_uuid=uuidsentinel.eph_encryption,
            networks=[])
        server_id = self._assert_build_request_success(server_request)
        self._assert_ephemeral_encryption_enabled(server_id)

    def test_flavor_and_image_disabled(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.eph_encryption_disabled_flavor,
            image_uuid=uuidsentinel.eph_encryption_disabled,
            networks=[])
        server_id = self._assert_build_request_success(server_request)
        self._assert_ephemeral_encryption_disabled(server_id)

    def test_flavor_requested_and_image_disabled(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.eph_encryption_flavor,
            image_uuid=uuidsentinel.eph_encryption_disabled,
            networks=[])
        self._assert_bad_build_request_error(server_request)

    def test_flavor_disabled_and_image_requested(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.eph_encryption_disabled_flavor,
            image_uuid=uuidsentinel.eph_encryption,
            networks=[])
        self._assert_bad_build_request_error(server_request)


class TestEphemeralEncryptionUnavailable(_TestEphemeralEncryptionBase):

    compute_driver = 'fake.MediumFakeDriver'
    flavors = {
        'no_eph_encryption': {
            'id': uuidsentinel.no_eph_encryption
        },
        'eph_encryption': {
            'id': uuidsentinel.eph_encryption_flavor,
            'extra_specs': {
                'hw:ephemeral_encryption': 'True'
            }
        },
        'eph_encryption_disabled': {
            'id': uuidsentinel.eph_encryption_disabled_flavor,
            'extra_specs': {
                'hw:ephemeral_encryption': 'False'
            }
        },
    }

    def test_requested_but_unavailable(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.eph_encryption_flavor,
            image_uuid=uuidsentinel.eph_encryption,
            networks=[])
        self._assert_build_request_schedule_failure(server_request)

    def test_image_disabled(self):
        server_request = self._build_server(
            image_uuid=uuidsentinel.eph_encryption_disabled,
            flavor_id=uuidsentinel.no_eph_encryption,
            networks=[])
        server_id = self._assert_build_request_success(server_request)
        self._assert_ephemeral_encryption_disabled(server_id)

    def test_flavor_disabled(self):
        server_request = self._build_server(
            flavor_id=uuidsentinel.eph_encryption_disabled_flavor,
            networks=[])
        server_id = self._assert_build_request_success(server_request)
        self._assert_ephemeral_encryption_disabled(server_id)


class TestEphemeralEncryptionResize(_TestEphemeralEncryptionBase):

    compute_driver = 'fake.EphEncryptionDriver'
    flavors = {
        'no_eph_encryption': {
            'id': uuidsentinel.no_eph_encryption
        },
        'eph_encryption': {
            'id': uuidsentinel.eph_encryption_flavor,
            'extra_specs': {
                'hw:ephemeral_encryption': 'True'
            }
        },
        'eph_encryption_disabled': {
            'id': uuidsentinel.eph_encryption_disabled_flavor,
            'extra_specs': {
                'hw:ephemeral_encryption': 'False'
            }
        },
    }

    def test_flavor_encryption_requested_mismatch(self):
        # Test a scenario where the current flavor does not have ephemeral
        # encryption specified but the new flavor does have it.
        server = self._create_server(
            flavor_id=uuidsentinel.no_eph_encryption, networks=[])
        ex = self.assertRaises(
            api_client.OpenStackApiException, self._resize_server, server,
            uuidsentinel.eph_encryption_flavor)
        self.assertEqual(400, ex.response.status_code)

    def test_flavor_encryption_enabled_mismatch(self):
        # Test a scenario where the current flavor has ephemeral encryption
        # specified but the new flavor has it disabled.
        server = self._create_server(
            flavor_id=uuidsentinel.eph_encryption_flavor, networks=[])
        ex = self.assertRaises(
            api_client.OpenStackApiException, self._resize_server, server,
            uuidsentinel.eph_encryption_disabled_flavor)
        self.assertEqual(400, ex.response.status_code)

    def test_flavor_encryption_not_specified_to_disabled(self):
        # Start another compute to be the resize destination.
        self._start_compute(host='compute2')
        # Test a scenario where the current flavor doesn't specify ephemeral
        # encryption and the new flavor has it disabled. This should be
        # allowed.
        server = self._create_server(
            flavor_id=uuidsentinel.no_eph_encryption, networks=[])
        # Resize should not be rejected.
        self._resize_server(
            server, uuidsentinel.eph_encryption_disabled_flavor)

    def test_flavor_encryption_disabled_image_enabled(self):
        # Test a scenario where the current image of the instance has
        # encryption enabled but the flavor requested for the resize has it
        # disabled.
        properties = {'hw_ephemeral_encryption': 'true'}
        image_id = self._create_image(properties)['id']
        server = self._create_server(
            flavor_id=uuidsentinel.no_eph_encryption, image_uuid=image_id,
            networks=[])
        ex = self.assertRaises(
            api_client.OpenStackApiException, self._resize_server, server,
            uuidsentinel.eph_encryption_disabled_flavor)
        self.assertEqual(400, ex.response.status_code)
