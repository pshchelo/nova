# Copyright 2012 Grid Dynamics
# Copyright 2013 Inktank Storage, Inc.
# Copyright 2014 Mirantis, Inc.
#
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

import contextlib
import re
import tempfile
import typing as ty
import urllib.parse

from oslo_concurrency import processutils
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_service import loopingcall
from oslo_utils import encodeutils
from oslo_utils import excutils
from oslo_utils import units
from oslo_utils import versionutils

import nova.conf
from nova import exception
from nova.i18n import _
from nova.objects import encrypt_details
from nova.objects import fields
from nova import utils

try:
    import rados
    import rbd
except ImportError:
    rados = None
    rbd = None

CONF = nova.conf.CONF

LOG = logging.getLogger(__name__)

RESIZE_SNAPSHOT_NAME = 'nova-resize'


class EncryptionInfo(ty.TypedDict):
    secret: str
    format: str
    details: encrypt_details.EncryptDetails
    backing_secret: str


class RbdProxy(object):
    """A wrapper around rbd.RBD class instance to avoid blocking of process.

    Offloads all calls to rbd.RBD class methods to native OS threads, so that
    we do not block the whole process while executing the librbd code.

    """

    def __init__(self):
        self._rbd = utils.tpool_wrap(rbd.RBD())

    def __getattr__(self, attr):
        return getattr(self._rbd, attr)


class RBDVolumeProxy(object):
    """Context manager for dealing with an existing rbd volume.

    This handles connecting to rados and opening an ioctx automatically, and
    otherwise acts like a librbd Image object.

    The underlying librados client and ioctx can be accessed as the attributes
    'client' and 'ioctx'.
    """

    def __init__(self, driver, name, pool=None, snapshot=None,
                 read_only=False):
        client, ioctx = driver._connect_to_rados(pool)
        try:
            self.volume = utils.tpool_wrap(
                rbd.Image(ioctx, name, snapshot=snapshot, read_only=read_only))
        except rbd.ImageNotFound:
            with excutils.save_and_reraise_exception():
                LOG.debug("rbd image %s does not exist", name)
                driver._disconnect_from_rados(client, ioctx)
        except rbd.Error:
            with excutils.save_and_reraise_exception():
                LOG.exception("error opening rbd image %s", name)
                driver._disconnect_from_rados(client, ioctx)

        self.driver = driver
        self.client = client
        self.ioctx = ioctx

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        try:
            self.volume.close()
        finally:
            self.driver._disconnect_from_rados(self.client, self.ioctx)

    def __getattr__(self, attrib):
        return getattr(self.volume, attrib)


class RADOSClient(object):
    """Context manager to simplify error handling for connecting to ceph."""

    def __init__(self, driver, pool=None):
        self.driver = driver
        self.cluster, self.ioctx = driver._connect_to_rados(pool)

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.driver._disconnect_from_rados(self.cluster, self.ioctx)

    @property
    def features(self):
        features = self.cluster.conf_get('rbd_default_features')
        if ((features is None) or (int(features) == 0)):
            features = rbd.RBD_FEATURE_LAYERING
        return int(features)


class RBDDriver(object):

    def __init__(self, pool=None, user=None, ceph_conf=None,
                 connect_timeout=None):

        # NOTE(lyarwood): Ensure the rbd and rados modules have been imported
        # correctly before continuing, this is done in a separate private
        # method to allow us to skip this check in unit tests etc.
        self._check_for_import_failure()

        self.pool = pool or CONF.libvirt.images_rbd_pool
        self.rbd_user = user or CONF.libvirt.rbd_user
        self.rbd_connect_timeout = (
            connect_timeout or CONF.libvirt.rbd_connect_timeout)
        self.ceph_conf = ceph_conf or CONF.libvirt.images_rbd_ceph_conf

    def _check_for_import_failure(self):
        # NOTE(lyarwood): If the original import of the required rbd or rados
        # modules failed then repeat the imports at runtime within this driver
        # to log the full exception in order to provide context to anyone
        # debugging the failure in the logs.
        global rados, rbd
        if rbd is None or rados is None:
            try:
                # NOTE(lyarwood): noqa is required on both imports here as they
                # are unused (F401) even if successful.
                import rados  # noqa: F401
                import rbd  # noqa: F401
            except ImportError:
                LOG.exception("Unable to import the rados or rbd modules")

            raise RuntimeError(_('rbd python libraries not found'))

    def _connect_to_rados(self, pool=None):
        client = rados.Rados(rados_id=self.rbd_user,
                                  conffile=self.ceph_conf)
        try:
            client.connect(timeout=self.rbd_connect_timeout)
            pool_to_open = pool or self.pool
            # NOTE(luogangyi): open_ioctx >= 10.1.0 could handle unicode
            # arguments perfectly as part of Python 3 support.
            # Therefore, when we turn to Python 3, it's safe to remove
            # str() conversion.
            ioctx = client.open_ioctx(str(pool_to_open))
            return client, ioctx
        except rados.Error:
            # shutdown cannot raise an exception
            client.shutdown()
            raise

    def _disconnect_from_rados(self, client, ioctx):
        # closing an ioctx cannot raise an exception
        ioctx.close()
        client.shutdown()

    def ceph_args(self):
        """List of command line parameters to be passed to ceph commands to
           reflect RBDDriver configuration such as RBD user name and location
           of ceph.conf.
        """
        args = []
        if self.rbd_user:
            args.extend(['--id', self.rbd_user])
        if self.ceph_conf:
            args.extend(['--conf', self.ceph_conf])
        return args

    def get_ceph_version(self) -> str:
        """Get the Ceph version in X.Y.Z format"""
        args = ['ceph', '--version']
        out, _ = processutils.execute(*args)
        m = re.search(r'\d+\.\d+\.\d+', out)
        if not m:
            raise exception.NotFound('Ceph version could not be found.')
        return m.group(0)

    def is_clone(self, name: str, pool: ty.Optional[str] = None) -> bool:
        with RBDVolumeProxy(self, name, pool=pool) as vol:
            try:
                vol.parent_id()
            except rbd.ImageNotFound:
                return False
            return True

    def get_mon_addrs(self, strip_brackets=True):
        args = ['ceph', 'mon', 'dump', '--format=json'] + self.ceph_args()
        out, _ = processutils.execute(*args)
        lines = out.split('\n')
        if lines[0].startswith('dumped monmap epoch'):
            lines = lines[1:]
        monmap = jsonutils.loads('\n'.join(lines))
        addrs = [mon['addr'] for mon in monmap['mons']]
        hosts = []
        ports = []
        for addr in addrs:
            host_port = addr[:addr.rindex('/')]
            host, port = host_port.rsplit(':', 1)
            if strip_brackets:
                host = host.strip('[]')
            hosts.append(host)
            ports.append(port)
        return hosts, ports

    def parse_url(self, url):
        prefix = 'rbd://'
        if not url.startswith(prefix):
            reason = _('Not stored in rbd')
            raise exception.ImageUnacceptable(image_id=url, reason=reason)
        pieces = [urllib.parse.unquote(piece)
                  for piece in url[len(prefix):].split('/')]
        if '' in pieces:
            reason = _('Blank components')
            raise exception.ImageUnacceptable(image_id=url, reason=reason)
        if len(pieces) != 4:
            reason = _('Not an rbd snapshot')
            raise exception.ImageUnacceptable(image_id=url, reason=reason)
        return pieces

    def get_fsid(self):
        with RADOSClient(self) as client:
            return encodeutils.safe_decode(client.cluster.get_fsid())

    def is_cloneable(self, image_location, image_meta):
        url = image_location['url']
        try:
            fsid, pool, image, snapshot = self.parse_url(url)
        except exception.ImageUnacceptable as e:
            LOG.debug('not cloneable: %s', e)
            return False

        fsid = encodeutils.safe_decode(fsid)
        if self.get_fsid() != fsid:
            reason = '%s is in a different ceph cluster' % url
            LOG.debug(reason)
            return False

        if image_meta.get('disk_format') != 'raw':
            LOG.debug("rbd image clone requires image format to be "
                      "'raw' but image %s is '%s'",
                      url, image_meta.get('disk_format'))
            return False

        # check that we can read the image
        try:
            return self.exists(image, pool=pool, snapshot=snapshot)
        except rbd.Error as e:
            LOG.debug('Unable to open image %(loc)s: %(err)s',
                      dict(loc=url, err=e))
            return False

    @property
    def supports_layered_encryption(self) -> bool:
        """Whether this version of Ceph supports layered encryption.

        If Ceph version <= 18.1.0 (Reef), creating clone images with
        encryption keys different from the parent is not supported.

        https://github.com/ceph/ceph/commit/1d3de19
        """
        return (versionutils.convert_version_to_int(self.get_ceph_version()) >=
                    versionutils.convert_version_to_int('18.1.0'))

    def load_encryption(
        self,
        image: 'rbd.Image',
        src_encryption: ty.Optional[EncryptionInfo] = None,
        dest_encryption: ty.Optional[EncryptionInfo] = None,
    ) -> None:
        """Load encryption for the specified image.

        "In order to safely perform encrypted IO on the formatted image, an
        additional encryption load operation should be applied after opening
        the image. The encryption load operation requires supplying the
        encryption format and a secret for unlocking the encryption key.
        Following a successful encryption load operation, all IOs for the
        opened image will be encrypted / decrypted. For a cloned image, this
        includes IOs for ancestor images as well. The encryption key will be
        stored in-memory by the RBD client until the image is closed."

        The ordering of the passphrases goes from outermost layer to innermost
        layer. For example:

                    snapshot image <-- VM image <-- source image

        https://docs.ceph.com/en/quincy/rbd/rbd-encryption/#encryption-load
        """
        # FIXME(melwitt): Instead of shelling out using the CLI, can _probably_
        # use the encryption_load2(self, specs) method:
        # https://github.com/ceph/ceph/blob/314e8e3c4009ffd757464ef2820ebe906d1575c3/src/pybind/rbd/rbd.pyx#L5289
        # where 'specs' appears to be a list of tuples (format, passphrase).
        # Then after doing encryption_load2(), call the normal resize or
        # flatten methods afterward.
        # encryption_load2() is in >= Reef ONLY. Otherwise you have to use
        # encryption_load(self, format, passphrase) which only accepts a single
        # format and passphrase.
        if not src_encryption and not dest_encryption:
            return

        specs = []
        if dest_encryption:
            dest_encryption_format = dest_encryption['format']
            if dest_encryption_format == 'luks':
                dest_encryption_format = rbd.RBD_ENCRYPTION_FORMAT_LUKS1
            LOG.debug(
                f"loading encryption for image {image.get_name()} with format "
                f"{dest_encryption['format']} ({dest_encryption_format}) ")
            # The librbd APIs require passphrases to be bytestrings, otherwise
            # they could be treated as wrong passphrases:
            #   rbd.PermissionError: [errno 1] RBD permission error
            #     (error loading encryption on image
            #      b'c18591d8-ecd4-4a08-b155-4d5dbb1cb7c7_disk')
            dest_secret = encodeutils.safe_encode(dest_encryption['secret'])
            specs += [(dest_encryption_format, dest_secret)]

            if 'backing_secret' in dest_encryption:
                dest_bsecret = encodeutils.safe_encode(
                    dest_encryption['backing_secret'])
                specs += [(dest_encryption_format, dest_bsecret)]

        if src_encryption:
            src_encryption_format = src_encryption['format']
            if src_encryption_format == 'luks':
                src_encryption_format = rbd.RBD_ENCRYPTION_FORMAT_LUKS1
            src_secret = encodeutils.safe_encode(src_encryption['secret'])
            specs += [(src_encryption_format, src_secret)]

            if 'backing_secret' in src_encryption:
                src_bsecret = encodeutils.safe_encode(
                    src_encryption['backing_secret'])
                specs += [(src_encryption_format, src_bsecret)]

        if not self.supports_layered_encryption:
            # If layered encryption is not supported, all passphrases in the
            # chain must be the same.
            image.encryption_load(specs[0][0], specs[0][1])
        else:
            print(f'specs = {specs}')
            image.encryption_load2(specs)

    def format_encryption(
        self,
        name: str,
        encryption: EncryptionInfo,
        pool: ty.Optional[str] = None,
    ) -> None:
        """Format an image for encryption.

        Make sure to consider the size of the encryption header when formatting
        an image. Example: if you clone an unformatted (unencrypted) image and
        then format the clone for encryption, the image *before cloning* must
        be large enough to accommodate the parent data + encryption header.
        This means that in cases like this, you will have to resize the image
        larger temporarily before cloning it.
        """
        # This is in here instead of global because the rbd module is
        # conditionally imported in this file.
        CIPHER_ALG_MAP = {
            fields.CipherAlgorithm.AES_128:
                rbd.RBD_ENCRYPTION_ALGORITHM_AES128,
            fields.CipherAlgorithm.AES_256:
                rbd.RBD_ENCRYPTION_ALGORITHM_AES256,
        }

        encryption_format = encryption['format']
        if encryption_format == 'luks':
            encryption_format = rbd.RBD_ENCRYPTION_FORMAT_LUKS1

        cipher_algorithm = encryption['details'].cipher_algorithm
        if cipher_algorithm not in CIPHER_ALG_MAP:
            raise exception.NotSupported(
                f'{cipher_algorithm} is not supported by RBD')
        cipher_alg = CIPHER_ALG_MAP[cipher_algorithm]

        encryption_secret: str | bytes = encodeutils.safe_encode(
            encryption['secret'])

        with RBDVolumeProxy(self, name, pool=pool) as vol:
            LOG.debug(
                f"formatting encryption for image {name} with format "
                f"{encryption['format']} ({encryption_format}) "
                f"and cipher algorithm "
                f"{encryption['details'].cipher_algorithm} ({cipher_alg})")
            vol.encryption_format(
                encryption_format, encryption_secret, cipher_alg=cipher_alg)

    def create(self, name, size):
        """Create a new empty image."""
        LOG.debug(f'creating image {self.pool}/{name} with size {size}')
        with RADOSClient(self, self.pool) as client:
            RbdProxy().create(client.ioctx, name, size)

    def clone(self, image_location, dest_name, dest_pool=None):
        _fsid, pool, image, snapshot = self.parse_url(
                image_location['url'])
        LOG.debug('cloning %(pool)s/%(img)s@%(snap)s to '
                  '%(dest_pool)s/%(dest_name)s',
                  dict(pool=pool, img=image, snap=snapshot,
                       dest_pool=dest_pool or self.pool, dest_name=dest_name))
        with RADOSClient(self, str(pool)) as src_client:
            with RADOSClient(self, dest_pool) as dest_client:
                try:
                    RbdProxy().clone(src_client.ioctx,
                                     image,
                                     snapshot,
                                     dest_client.ioctx,
                                     str(dest_name),
                                     features=src_client.features)
                except rbd.PermissionError:
                    raise exception.Forbidden(_('no write permission on '
                                                'storage pool %s') % dest_pool)

    def size(self, name, pool=None):
        with RBDVolumeProxy(self, name, read_only=True, pool=pool) as vol:
            return vol.size()

    def resize(self, name, size, pool=None, encryption=None):
        """Resize RBD volume.

        :name: Name of RBD object
        :size: New size in bytes
        """
        LOG.debug('resizing rbd image %s to %d', name, size)
        with RBDVolumeProxy(self, name, pool=pool) as vol:
            delta = 0
            if encryption and not self.supports_layered_encryption:
                # NOTE(melwitt): Prior to layered encryption support, resize()
                # was not encryption-aware (even after loading encryption) in
                # that it didn't take into account the size of the LUKS header,
                # so resizing an encrypted image would result in a smaller
                # usable size than was specified. The size() function however
                # *does* account for the LUKS overhead. We need to calculate
                # the delta and include it in the resize in this case so that
                # there is enough room for the data we intend to copy into the
                # image after resizing, for example.
                actual_size = vol.size()
            self.load_encryption(vol, dest_encryption=encryption)
            if encryption and not self.supports_layered_encryption:
                effective_size = vol.size()
                delta = actual_size - effective_size
            vol.resize(size + delta)

    # TODO(melwitt): Remove this
    def resize_with_encryption(
        self,
        name: str,
        size: int,
        encryption: EncryptionInfo,
        pool: ty.Optional[str] = None,
    ) -> None:
        """Resizes an encrypted image.

        When the clone image is encrypted, the encryption format and passphrase
        must be supplied in order to perform the resizing. The Python bindings
        don't provide a way to pass the format and passphrase, so we have to
        use the CLI here.
        """
        with contextlib.ExitStack() as stack:
            secret_file = stack.enter_context(
                tempfile.NamedTemporaryFile(mode='tr+', encoding='utf-8'))
            # Write out the passphrase secret to a temp file
            secret_file.write(encryption['secret'])
            # Ensure the secret is written to disk, we can't .close() here as
            # that removes the file when using NamedTemporaryFile
            secret_file.flush()

            encryption_format = encryption['format']
            if encryption_format == 'luks':
                encryption_format = 'luks1'
            args = [
                'rbd', 'resize', '--size', f'{int(size / units.Mi)}M',
                '--allow-shrink', '--encryption-format', encryption_format,
                '--encryption-passphrase-file', secret_file.name]

            if 'backing_secret' in encryption:
                backing_secret_file = stack.enter_context(
                    tempfile.NamedTemporaryFile(mode='tr+', encoding='utf-8'))
                backing_secret_file.write(encryption['backing_secret'])
                backing_secret_file.flush()
                args += [
                    '--encryption-format', encryption_format,
                    '--encryption-passphrase-file', backing_secret_file.name]

            args += ['/'.join([pool or self.pool, name])] + self.ceph_args()
            processutils.execute(*args)

    def parent_info(self, volume, pool=None):
        """Returns the pool, image and snapshot name for the parent of an
        RBD volume.

        :volume: Name of RBD object
        :pool: Name of pool
        """
        try:
            with RBDVolumeProxy(self, str(volume), pool=pool,
                                read_only=True) as vol:
                return vol.parent_info()
        except rbd.ImageNotFound:
            raise exception.ImageUnacceptable(_("no usable parent snapshot "
                                                "for volume %s") % volume)

    def flatten(
            self, volume, pool=None, src_encryption=None,
            dest_encryption=None):
        """"Flattens" a snapshotted image with the parents' data, effectively
        detaching it from the parent.

        :volume: Name of RBD object
        :pool: Name of pool
        """
        LOG.debug('flattening %(pool)s/%(vol)s', dict(pool=pool, vol=volume))
        print(f'src_encryption = {src_encryption}')
        print(f'dest_encryption = {dest_encryption}')
        with RBDVolumeProxy(self, str(volume), pool=pool) as vol:
            # NOTE(melwitt): Encryption should only be loaded "if a clone of an
            # encrypted image is explicitly formatted", which will only be the
            # case if layered encryption is supported. That is, we are only
            # formatting clones if layered encryption is available, otherwise
            # we don't format them. Attempting to load encryption if the clone
            # has *not* been explicitly formatted results in an error like:
            #   rbd.InvalidArgument: [errno 22] RBD invalid argument (error
            #     loading encryption on image
            #     b'53028e8f-9484-45b8-aa45-716567a7ff33' with format luks1)
            # https://docs.ceph.com/en/latest/rbd/rbd-encryption/#encryption-load
            if self.supports_layered_encryption:
                self.load_encryption(
                    vol, src_encryption=src_encryption,
                    dest_encryption=dest_encryption)
            vol.flatten()

    # TODO(melwitt): Remove this
    def flatten_with_encryption(
        self,
        name: str,
        src_encryption: EncryptionInfo,
        dest_encryption: EncryptionInfo,
        pool: ty.Optional[str] = None
    ) -> None:
        """Flattens an encrypted clone image with its parent data.

        When the clone image is encrypted, the encryption format and passphrase
        must be supplied in order to perform the flattening. The Python
        bindings don't provide a way to pass the format and passphrase, so we
        have to use the CLI here.

        We can have up to 3 layers of encryption here (we can assume
        a maximum of 3 layers because we flatten our snapshots before uploading
        to Glance). Example: an instance booted by cloning  an encrypted source
        image is being snapshotted and flattened here -- there will be
        a passphrase for the parent encrypted source image, a passphrase for
        the current encrypted disk, and finally a passphrase for the clone
        we're flattening now.
        """
        with contextlib.ExitStack() as stack:
            args = ['rbd', 'flatten']

            # Ordering of passphrases needs to be the most recent or
            # "outermost" clone B, the parent of clone B (clone A), and the
            # parent of clone A:
            # clone B passphrase, clone A passphrase, parent passphrase.
            if dest_encryption:
                dest_secret_file = stack.enter_context(
                    tempfile.NamedTemporaryFile(mode='tr+', encoding='utf-8'))
                # Write out the passphrase secret to a temp file
                dest_secret_file.write(dest_encryption['secret'])
                # Ensure the secret is written to disk, we can't .close() here
                # as that removes the file when using NamedTemporaryFile
                dest_secret_file.flush()

                encryption_format = dest_encryption['format']
                if encryption_format == 'luks':
                    encryption_format = 'luks1'

                args += [
                    '--encryption-format', encryption_format,
                    '--encryption-passphrase-file', dest_secret_file.name]

            if src_encryption:
                src_secret_file = stack.enter_context(
                    tempfile.NamedTemporaryFile(mode='tr+', encoding='utf-8'))
                # Write out the passphrase secret to a temp file
                src_secret_file.write(src_encryption['secret'])
                # Ensure the secret is written to disk, we can't .close() here
                # as that removes the file when using NamedTemporaryFile
                src_secret_file.flush()

                encryption_format = src_encryption['format']
                if encryption_format == 'luks':
                    encryption_format = 'luks1'

                args += [
                    '--encryption-format', encryption_format,
                    '--encryption-passphrase-file', src_secret_file.name]

                if 'backing_secret' in src_encryption:
                    src_backing_secret_file = stack.enter_context(
                        tempfile.NamedTemporaryFile(
                            mode='tr+', encoding='utf-8'))
                    src_backing_secret_file.write(
                        src_encryption['backing_secret'])
                    src_backing_secret_file.flush()
                    args += [
                        '--encryption-format', encryption_format,
                        '--encryption-passphrase-file',
                        src_backing_secret_file.name]

            args += ['/'.join([pool or self.pool, name])] + self.ceph_args()
            processutils.execute(*args)

    def exists(self, name, pool=None, snapshot=None):
        try:
            with RBDVolumeProxy(self, name,
                                pool=pool,
                                snapshot=snapshot,
                                read_only=True):
                return True
        except rbd.ImageNotFound:
            return False

    def remove_image(self, name):
        """Remove RBD volume

        :name: Name of RBD volume
        """
        with RADOSClient(self, self.pool) as client:
            try:
                RbdProxy().remove(client.ioctx, name)
            except rbd.ImageNotFound:
                LOG.warning('image %(volume)s in pool %(pool)s can not be '
                            'found, failed to remove',
                            {'volume': name, 'pool': self.pool})
            except rbd.ImageHasSnapshots:
                LOG.error('image %(volume)s in pool %(pool)s has '
                          'snapshots, failed to remove',
                          {'volume': name, 'pool': self.pool})

    def import_image(self, base, name):
        """Import RBD volume from image file.

        Uses the command line import instead of librbd since rbd import
        command detects zeroes to preserve sparseness in the image.

        :base: Path to image file
        :name: Name of RBD volume
        """
        args = ['--pool', self.pool, base, name]
        # Image format 2 supports cloning,
        # in stable ceph rbd release default is not 2,
        # we need to use it explicitly.
        args += ['--image-format=2']
        args += self.ceph_args()
        processutils.execute('rbd', 'import', *args)

    def export_image(self, base, name, snap, pool=None):
        """Export RBD volume to image file.

        Uses the command line export to export rbd volume snapshot to
        local image file.

        :base: Path to image file
        :name: Name of RBD volume
        :snap: Name of RBD snapshot
        :pool: Name of RBD pool
        """
        if pool is None:
            pool = self.pool

        args = ['--pool', pool, '--image', name, '--path', base,
                '--snap', snap]
        args += self.ceph_args()
        processutils.execute('rbd', 'export', *args)

    def _destroy_volume(self, client, volume, pool=None):
        """Destroy an RBD volume, retrying as needed.
        """
        def _cleanup_vol(ioctx, volume, retryctx):
            try:
                RbdProxy().remove(ioctx, volume)
                raise loopingcall.LoopingCallDone(retvalue=False)
            except rbd.ImageHasSnapshots:
                self.remove_snap(volume, RESIZE_SNAPSHOT_NAME,
                                 ignore_errors=True)
            except (rbd.ImageBusy, rbd.ImageHasSnapshots):
                LOG.warning('rbd remove %(volume)s in pool %(pool)s failed',
                            {'volume': volume, 'pool': self.pool})
            retryctx['retries'] -= 1
            if retryctx['retries'] <= 0:
                raise loopingcall.LoopingCallDone()

        # NOTE(sandonov): We let it go for:
        # rbd_destroy_volume_retries*rbd_destroy_volume_retry_interval seconds
        retryctx = {'retries': CONF.libvirt.rbd_destroy_volume_retries}
        timer = loopingcall.FixedIntervalLoopingCall(
            _cleanup_vol, client.ioctx, volume, retryctx)
        timed_out = timer.start(
            interval=CONF.libvirt.rbd_destroy_volume_retry_interval).wait()
        if timed_out:
            # NOTE(danms): Run this again to propagate the error, but
            # if it succeeds, don't raise the loopingcall exception
            try:
                _cleanup_vol(client.ioctx, volume, retryctx)
            except loopingcall.LoopingCallDone:
                pass

    def cleanup_volumes(self, filter_fn):
        with RADOSClient(self, self.pool) as client:
            volumes = RbdProxy().list(client.ioctx)
            for volume in filter(filter_fn, volumes):
                self._destroy_volume(client, volume)

    def get_pool_info(self):
        # NOTE(melwitt): We're executing 'ceph df' here instead of calling
        # the RADOSClient.get_cluster_stats python API because we need
        # access to the MAX_AVAIL stat, which reports the available bytes
        # taking replication into consideration. The global available stat
        # from the RADOSClient.get_cluster_stats python API does not take
        # replication size into consideration and will simply return the
        # available storage per OSD, added together across all OSDs. The
        # MAX_AVAIL stat will divide by the replication size when doing the
        # calculation.
        args = ['ceph', 'df', '--format=json'] + self.ceph_args()

        try:
            out, _ = processutils.execute(*args)
        except processutils.ProcessExecutionError:
            LOG.exception('Could not determine disk usage')
            raise exception.StorageError(
                reason='Could not determine disk usage')

        stats = jsonutils.loads(out)

        # Find the pool for which we are configured.
        pool_stats = None
        for pool in stats['pools']:
            if pool['name'] == self.pool:
                pool_stats = pool['stats']
                break

        if pool_stats is None:
            raise exception.NotFound('Pool %s could not be found.' % self.pool)

        return {'total': stats['stats']['total_bytes'],
                'free': pool_stats['max_avail'],
                'used': pool_stats['bytes_used']}

    def create_snap(self, volume, name, pool=None, protect=False):
        """Create a snapshot of an RBD volume.

        :volume: Name of RBD object
        :name: Name of snapshot
        :pool: Name of pool
        :protect: Set the snapshot to "protected"
        """
        LOG.debug('creating snapshot(%(snap)s) on rbd image(%(img)s)',
                  {'snap': name, 'img': volume})
        with RBDVolumeProxy(self, str(volume), pool=pool) as vol:
            vol.create_snap(name)
            if protect and not vol.is_protected_snap(name):
                vol.protect_snap(name)

    def remove_snap(self, volume, name, ignore_errors=False, pool=None,
                    force=False):
        """Removes a snapshot from an RBD volume.

        :volume: Name of RBD object
        :name: Name of snapshot
        :ignore_errors: whether or not to log warnings on failures
        :pool: Name of pool
        :force: Remove snapshot even if it is protected
        """
        with RBDVolumeProxy(self, str(volume), pool=pool) as vol:
            if name in [snap.get('name', '') for snap in vol.list_snaps()]:
                if vol.is_protected_snap(name):
                    if force:
                        vol.unprotect_snap(name)
                    elif not ignore_errors:
                        LOG.warning('snapshot(%(name)s) on rbd '
                                    'image(%(img)s) is protected, skipping',
                                    {'name': name, 'img': volume})
                        return
                LOG.debug('removing snapshot(%(name)s) on rbd image(%(img)s)',
                          {'name': name, 'img': volume})
                vol.remove_snap(name)
            elif not ignore_errors:
                LOG.warning('no snapshot(%(name)s) found on rbd '
                            'image(%(img)s)',
                            {'name': name, 'img': volume})

    def rollback_to_snap(self, volume, name):
        """Revert an RBD volume to its contents at a snapshot.

        :volume: Name of RBD object
        :name: Name of snapshot
        """
        with RBDVolumeProxy(self, volume) as vol:
            if name in [snap.get('name', '') for snap in vol.list_snaps()]:
                LOG.debug('rolling back rbd image(%(img)s) to '
                          'snapshot(%(snap)s)', {'snap': name, 'img': volume})
                vol.rollback_to_snap(name)
            else:
                raise exception.SnapshotNotFound(snapshot_id=name)

    def destroy_volume(self, volume, pool=None):
        """A one-shot version of cleanup_volumes()
        """
        with RADOSClient(self, pool) as client:
            self._destroy_volume(client, volume)
