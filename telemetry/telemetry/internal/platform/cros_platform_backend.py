# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from telemetry import decorators
from telemetry.core import cros_interface
from telemetry.core import platform
from telemetry.core import util
from telemetry.internal.forwarders import cros_forwarder
from telemetry.internal.platform import cros_device
from telemetry.internal.platform import linux_based_platform_backend


class CrosPlatformBackend(
    linux_based_platform_backend.LinuxBasedPlatformBackend):
  def __init__(self, device=None):
    super(CrosPlatformBackend, self).__init__(device)
    if device and not device.is_local:
      self._cri = cros_interface.CrOSInterface(
          device.host_name, device.ssh_port, device.ssh_identity)
      self._cri.TryLogin()
    else:
      self._cri = cros_interface.CrOSInterface()

  def GetDeviceId(self):
    return self._cri.hostname

  @classmethod
  def IsPlatformBackendForHost(cls):
    return util.IsRunningOnCrosDevice()

  @classmethod
  def SupportsDevice(cls, device):
    return isinstance(device, cros_device.CrOSDevice)

  @classmethod
  def CreatePlatformForDevice(cls, device, finder_options):
    assert cls.SupportsDevice(device)
    return platform.Platform(CrosPlatformBackend(device))

  @property
  def cri(self):
    return self._cri

  def _CreateForwarderFactory(self):
    return cros_forwarder.CrOsForwarderFactory(self._cri)

  def GetRemotePort(self, port):
    if self._cri.local:
      return port
    return self._cri.GetRemotePort()

  def IsRemoteDevice(self):
    # Check if CrOS device is remote.
    return self._cri and not self._cri.local

  def IsThermallyThrottled(self):
    raise NotImplementedError()

  def HasBeenThermallyThrottled(self):
    raise NotImplementedError()

  def RunCommand(self, args):
    if not isinstance(args, list):
      args = [args]
    stdout, stderr = self._cri.RunCmdOnDevice(args)
    if stderr:
      raise IOError('Failed to run: cmd = %s, stderr = %s' %
                    (str(args), stderr))
    return stdout

  def StartCommand(self, args, cwd=None, quiet=False, connect_timeout=None):
    if not isinstance(args, list):
      args = [args]
    return self._cri.StartCmdOnDevice(args, cwd, quiet, connect_timeout)

  def GetFile(self, filename, destfile=None):
    return self._cri.GetFile(filename, destfile)

  def GetFileContents(self, filename):
    try:
      return self.RunCommand(['cat', filename])
    except AssertionError:
      return ''

  def PushContents(self, text, remote_filename):
    return self._cri.PushContents(text, remote_filename)

  def GetDeviceTypeName(self):
    return self._cri.GetDeviceTypeName()

  @decorators.Cache
  def GetArchName(self):
    return self._cri.GetArchName()

  def GetOSName(self):
    return 'chromeos'

  def GetOSVersionName(self):
    return ''  # TODO: Implement this.

  def GetOSVersionDetailString(self):
    return ''  # TODO(kbr): Implement this.

  def CanFlushIndividualFilesFromSystemCache(self):
    return True

  def FlushEntireSystemCache(self):
    raise NotImplementedError()

  def FlushSystemCacheForDirectory(self, directory):
    flush_command = (
        '/usr/local/telemetry/src/src/out/Release/clear_system_cache')
    self.RunCommand(['chmod', '+x', flush_command])
    self.RunCommand([flush_command, '--recurse', directory])

  def PathExists(self, path, timeout=None, retries=None):
    if timeout or retries:
      logging.warning(
          'PathExists: params timeout and retries are not support on CrOS.')
    return self._cri.FileExistsOnDevice(path)

  def CanTakeScreenshot(self):
    # crbug.com/609001: screenshots don't work on VMs.
    return not self.cri.IsRunningOnVM()

  def TakeScreenshot(self, file_path):
    return self._cri.TakeScreenshot(file_path)

  def GetTypExpectationsTags(self):
    tags = super(CrosPlatformBackend, self).GetTypExpectationsTags()
    tags.append('desktop')
    if self.cri.local:
      tags.append('chromeos-local')
    else:
      tags.append('chromeos-remote')
    return tags
