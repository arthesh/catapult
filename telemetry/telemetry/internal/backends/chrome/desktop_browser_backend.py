# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import datetime
import logging
import os
import os.path
import random
import re
import shutil
import signal
import subprocess as subprocess
import sys
import tempfile
import time

import py_utils
from py_utils import cloud_storage
from py_utils import exc_util

from telemetry.core import exceptions
from telemetry.internal.backends.chrome import chrome_browser_backend
from telemetry.internal.backends.chrome import minidump_finder
from telemetry.internal.backends.chrome import desktop_minidump_symbolizer
from telemetry.internal.util import format_for_logging


DEVTOOLS_ACTIVE_PORT_FILE = 'DevToolsActivePort'


class DesktopBrowserBackend(chrome_browser_backend.ChromeBrowserBackend):
  """The backend for controlling a locally-executed browser instance, on Linux,
  Mac or Windows.
  """
  def __init__(self, desktop_platform_backend, browser_options,
               browser_directory, profile_directory,
               executable, flash_path, is_content_shell):
    super(DesktopBrowserBackend, self).__init__(
        desktop_platform_backend,
        browser_options=browser_options,
        browser_directory=browser_directory,
        profile_directory=profile_directory,
        supports_extensions=not is_content_shell,
        supports_tab_control=not is_content_shell)
    self._executable = executable
    self._flash_path = flash_path
    self._is_content_shell = is_content_shell

    # Initialize fields so that an explosion during init doesn't break in Close.
    self._proc = None
    self._tmp_output_file = None
    self._dump_finder = None
    # pylint: disable=invalid-name
    self._most_recent_symbolized_minidump_paths = set([])
    self._minidump_path_crashpad_retrieval = {}
    # pylint: enable=invalid-name

    if not self._executable:
      raise Exception('Cannot create browser, no executable found!')

    if self._flash_path and not os.path.exists(self._flash_path):
      raise RuntimeError('Flash path does not exist: %s' % self._flash_path)

    self._tmp_minidump_dir = tempfile.mkdtemp()
    if self.is_logging_enabled:
      self._log_file_path = os.path.join(tempfile.mkdtemp(), 'chrome.log')
    else:
      self._log_file_path = None

  @property
  def is_logging_enabled(self):
    return self.browser_options.logging_verbosity in [
        self.browser_options.NON_VERBOSE_LOGGING,
        self.browser_options.VERBOSE_LOGGING,
        self.browser_options.SUPER_VERBOSE_LOGGING]

  @property
  def log_file_path(self):
    return self._log_file_path

  @property
  def supports_uploading_logs(self):
    return (self.browser_options.logs_cloud_bucket and self.log_file_path and
            os.path.isfile(self.log_file_path))

  def _GetDevToolsActivePortPath(self):
    return os.path.join(self.profile_directory, DEVTOOLS_ACTIVE_PORT_FILE)

  def _FindDevToolsPortAndTarget(self):
    devtools_file_path = self._GetDevToolsActivePortPath()
    if not os.path.isfile(devtools_file_path):
      raise EnvironmentError('DevTools file doest not exist yet')
    # Attempt to avoid reading the file until it's populated.
    # Both stat and open may raise IOError if not ready, the caller will retry.
    lines = None
    if os.stat(devtools_file_path).st_size > 0:
      with open(devtools_file_path) as f:
        lines = [line.rstrip() for line in f]
    if not lines:
      raise EnvironmentError('DevTools file empty')

    devtools_port = int(lines[0])
    browser_target = lines[1] if len(lines) >= 2 else None
    return devtools_port, browser_target

  def Start(self, startup_args):
    assert not self._proc, 'Must call Close() before Start()'

    self._dump_finder = minidump_finder.MinidumpFinder(
        self.browser.platform.GetOSName(), self.browser.platform.GetArchName())

    # macOS displays a blocking crash resume dialog that we need to suppress.
    if self.browser.platform.GetOSName() == 'mac':
      # Default write expects either the application name or the
      # path to the application. self._executable has the path to the app
      # with a few other bits tagged on after .app. Thus, we shorten the path
      # to end with .app. If this is ineffective on your mac, please delete
      # the saved state of the browser you are testing on here:
      # /Users/.../Library/Saved\ Application State/...
      # http://stackoverflow.com/questions/20226802
      dialog_path = re.sub(r'\.app\/.*', '.app', self._executable)
      subprocess.check_call([
          'defaults', 'write', '-app', dialog_path, 'NSQuitAlwaysKeepsWindows',
          '-bool', 'false'
      ])

    cmd = [self._executable]
    if self.browser.platform.GetOSName() == 'mac':
      cmd.append('--use-mock-keychain')  # crbug.com/865247
    cmd.extend(startup_args)
    cmd.append('about:blank')
    env = os.environ.copy()
    env['CHROME_HEADLESS'] = '1'  # Don't upload minidumps.
    env['BREAKPAD_DUMP_LOCATION'] = self._tmp_minidump_dir
    if self.is_logging_enabled:
      sys.stderr.write(
          'Chrome log file will be saved in %s\n' % self.log_file_path)
      env['CHROME_LOG_FILE'] = self.log_file_path
    # Make sure we have predictable language settings that don't differ from the
    # recording.
    for name in ('LC_ALL', 'LC_MESSAGES', 'LANG'):
      encoding = 'en_US.UTF-8'
      if env.get(name, encoding) != encoding:
        logging.warn('Overriding env[%s]=="%s" with default value "%s"',
                     name, env[name], encoding)
      env[name] = 'en_US.UTF-8'

    self.LogStartCommand(cmd, env)

    if not self.browser_options.show_stdout:
      self._tmp_output_file = tempfile.NamedTemporaryFile('w', 0)
      self._proc = subprocess.Popen(
          cmd, stdout=self._tmp_output_file, stderr=subprocess.STDOUT, env=env)
    else:
      self._proc = subprocess.Popen(cmd, env=env)

    self.BindDevToolsClient()
    # browser is foregrounded by default on Windows and Linux, but not Mac.
    if self.browser.platform.GetOSName() == 'mac':
      subprocess.Popen([
          'osascript', '-e',
          ('tell application "%s" to activate' % self._executable)
      ])
    if self._supports_extensions:
      self._WaitForExtensionsToLoad()

  def LogStartCommand(self, command, env):
    """Log the command used to start Chrome.

    In order to keep the length of logs down (see crbug.com/943650),
    we sometimes trim the start command depending on browser_options.
    The command may change between runs, but usually in innocuous ways like
    --user-data-dir changes to a new temporary directory. Some benchmarks
    do use different startup arguments for different stories, but this is
    discouraged. This method could be changed to print arguments that are
    different since the last run if need be.
    """
    formatted_command = format_for_logging.ShellFormat(
        command, trim=self.browser_options.trim_logs)
    logging.info('Starting Chrome: %s\n', formatted_command)
    if not self.browser_options.trim_logs:
      logging.info('Chrome Env: %s', env)

  def BindDevToolsClient(self):
    # In addition to the work performed by the base class, quickly check if
    # the browser process is still alive.
    if not self.IsBrowserRunning():
      raise exceptions.ProcessGoneException(
          'Return code: %d' % self._proc.returncode)
    super(DesktopBrowserBackend, self).BindDevToolsClient()

  def GetPid(self):
    if self._proc:
      return self._proc.pid
    return None

  def IsBrowserRunning(self):
    return self._proc and self._proc.poll() is None

  def GetStandardOutput(self):
    if not self._tmp_output_file:
      if self.browser_options.show_stdout:
        # This can happen in the case that loading the Chrome binary fails.
        # We print rather than using logging here, because that makes a
        # recursive call to this function.
        print >> sys.stderr, "Can't get standard output with --show-stdout"
      return ''
    self._tmp_output_file.flush()
    try:
      with open(self._tmp_output_file.name) as f:
        return f.read()
    except IOError:
      return ''

  def _IsExecutableStripped(self):
    if self.browser.platform.GetOSName() == 'mac':
      try:
        symbols = subprocess.check_output(['/usr/bin/nm', self._executable])
      except subprocess.CalledProcessError as err:
        logging.warning(
            'Error when checking whether executable is stripped: %s',
            err.output)
        # Just assume that binary is stripped to skip breakpad symbol generation
        # if this check failed.
        return True
      num_symbols = len(symbols.splitlines())
      # We assume that if there are more than 10 symbols the executable is not
      # stripped.
      return num_symbols < 10
    else:
      return False

  def _GetStackFromMinidump(self, minidump):
    dump_symbolizer = desktop_minidump_symbolizer.DesktopMinidumpSymbolizer(
        self.browser.platform.GetOSName(),
        self.browser.platform.GetArchName(),
        self._dump_finder, self.browser_directory)
    return dump_symbolizer.SymbolizeMinidump(minidump)

  def _UploadMinidumpToCloudStorage(self, minidump_path):
    """ Upload minidump_path to cloud storage and return the cloud storage url.
    """
    remote_path = ('minidump-%s-%i.dmp' %
                   (datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'),
                    random.randint(0, 1000000)))
    try:
      return cloud_storage.Insert(cloud_storage.TELEMETRY_OUTPUT, remote_path,
                                  minidump_path)
    except cloud_storage.CloudStorageError as err:
      logging.error('Cloud storage error while trying to upload dump: %s',
                    repr(err))
      return '<Missing link>'

  def GetStackTrace(self):
    most_recent_dump = self.GetMostRecentMinidumpPath()
    if not most_recent_dump:
      return (False, 'No crash dump found.')
    logging.info('Minidump found: %s', most_recent_dump)
    return self._InternalSymbolizeMinidump(most_recent_dump)

  def GetMostRecentMinidumpPath(self):
    dump_path, explanation = self._dump_finder.GetMostRecentMinidump(
        self._tmp_minidump_dir)
    logging.info('\n'.join(explanation))
    return dump_path

  def GetRecentMinidumpPathWithTimeout(self, timeout_s, oldest_ts):
    assert timeout_s > 0
    assert oldest_ts >= 0
    explanation = ['No explanation returned.']
    start_time = time.time()
    try:
      while time.time() - start_time < timeout_s:
        dump_path, explanation = self._dump_finder.GetMostRecentMinidump(
            self._tmp_minidump_dir)
        if not dump_path:
          continue
        if os.path.getmtime(dump_path) < oldest_ts:
          continue
        return dump_path
      return None
    finally:
      logging.info('\n'.join(explanation))

  def GetAllMinidumpPaths(self):
    paths, explanation = self._dump_finder.GetAllMinidumpPaths(
        self._tmp_minidump_dir)
    logging.info('\n'.join(explanation))
    return paths

  def GetAllUnsymbolizedMinidumpPaths(self):
    minidump_paths = set(self.GetAllMinidumpPaths())
    # If we have already symbolized paths remove them from the list
    unsymbolized_paths = (
        minidump_paths - self._most_recent_symbolized_minidump_paths)
    return list(unsymbolized_paths)

  def SymbolizeMinidump(self, minidump_path):
    return self._InternalSymbolizeMinidump(minidump_path)

  def _InternalSymbolizeMinidump(self, minidump_path):
    cloud_storage_link = self._UploadMinidumpToCloudStorage(minidump_path)

    stack = self._GetStackFromMinidump(minidump_path)
    if not stack:
      error_message = ('Failed to symbolize minidump. Raw stack is uploaded to'
                       ' cloud storage: %s.' % cloud_storage_link)
      return (False, error_message)

    self._most_recent_symbolized_minidump_paths.add(minidump_path)
    return (True, stack)

  def __del__(self):
    self.Close()

  def _TryCooperativeShutdown(self):
    if self.browser.platform.IsCooperativeShutdownSupported():
      # Ideally there would be a portable, cooperative shutdown
      # mechanism for the browser. This seems difficult to do
      # correctly for all embedders of the content API. The only known
      # problem with unclean shutdown of the browser process is on
      # Windows, where suspended child processes frequently leak. For
      # now, just solve this particular problem. See Issue 424024.
      if self.browser.platform.CooperativelyShutdown(self._proc, "chrome"):
        try:
          # Use a long timeout to handle slow Windows debug
          # (see crbug.com/815004)
          py_utils.WaitFor(lambda: not self.IsBrowserRunning(), timeout=15)
          logging.info('Successfully shut down browser cooperatively')
        except py_utils.TimeoutException as e:
          logging.warning('Failed to cooperatively shutdown. ' +
                          'Proceeding to terminate: ' + str(e))

  def Background(self):
    raise NotImplementedError

  @exc_util.BestEffort
  def Close(self):
    super(DesktopBrowserBackend, self).Close()

    # First, try to cooperatively shutdown.
    if self.IsBrowserRunning():
      self._TryCooperativeShutdown()

    # Second, try to politely shutdown with SIGINT.  Use SIGINT instead of
    # SIGTERM (or terminate()) here since the browser treats SIGTERM as a more
    # urgent shutdown signal and may not free all resources.
    if self.IsBrowserRunning() and self.browser.platform.GetOSName() != 'win':
      self._proc.send_signal(signal.SIGINT)
      try:
        py_utils.WaitFor(lambda: not self.IsBrowserRunning(), timeout=5)
        self._proc = None
      except py_utils.TimeoutException:
        logging.warning('Failed to gracefully shutdown.')

    # Shutdown aggressively if all above failed.
    if self.IsBrowserRunning():
      logging.warning('Proceed to kill the browser.')
      self._proc.kill()
    self._proc = None

    if self._tmp_output_file:
      self._tmp_output_file.close()
      self._tmp_output_file = None

    if self._tmp_minidump_dir:
      shutil.rmtree(self._tmp_minidump_dir, ignore_errors=True)
      self._tmp_minidump_dir = None
