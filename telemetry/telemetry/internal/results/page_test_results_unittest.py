# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import shutil
import sys
import tempfile
import unittest

import mock

from telemetry import story
from telemetry.core import exceptions
from telemetry.internal.results import page_test_results
from telemetry.internal.results import results_options
from telemetry import page as page_module
from tracing.trace_data import trace_data


def _CreateException():
  try:
    raise exceptions.IntentionalException
  except Exception: # pylint: disable=broad-except
    return sys.exc_info()


class PageTestResultsTest(unittest.TestCase):
  def setUp(self):
    story_set = story.StorySet()
    story_set.AddStory(page_module.Page("http://www.foo.com/", story_set,
                                        name='http://www.foo.com/'))
    story_set.AddStory(page_module.Page("http://www.bar.com/", story_set,
                                        name='http://www.bar.com/'))
    story_set.AddStory(page_module.Page("http://www.baz.com/", story_set,
                                        name='http://www.baz.com/'))
    self.story_set = story_set
    self._output_dir = tempfile.mkdtemp()
    self._time_module = mock.patch(
        'telemetry.internal.results.page_test_results.time').start()
    self._time_module.time.return_value = 0

  def tearDown(self):
    shutil.rmtree(self._output_dir)
    mock.patch.stopall()

  @property
  def pages(self):
    return self.story_set.stories

  @property
  def mock_time(self):
    return self._time_module.time

  @property
  def intermediate_dir(self):
    return os.path.join(self._output_dir, 'artifacts', 'test_run')

  def CreateResults(self, **kwargs):
    kwargs.setdefault('output_dir', self._output_dir)
    kwargs.setdefault('intermediate_dir', self.intermediate_dir)
    return page_test_results.PageTestResults(**kwargs)

  def GetResultRecords(self):
    results_file = os.path.join(
        self.intermediate_dir, page_test_results.TEST_RESULTS)
    with open(results_file) as f:
      return [json.loads(line) for line in f]

  def testFailures(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      results.Fail(_CreateException())
      results.DidRunPage(self.pages[0])

      results.WillRunPage(self.pages[1])
      results.DidRunPage(self.pages[1])

    all_story_runs = list(results.IterStoryRuns())
    self.assertEqual(len(all_story_runs), 2)
    self.assertTrue(results.had_failures)
    self.assertTrue(all_story_runs[0].failed)
    self.assertTrue(all_story_runs[1].ok)

  def testSkips(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      results.Skip('testing reason')
      results.DidRunPage(self.pages[0])

      results.WillRunPage(self.pages[1])
      results.DidRunPage(self.pages[1])

    all_story_runs = list(results.IterStoryRuns())
    self.assertTrue(all_story_runs[0].skipped)
    self.assertEqual(self.pages[0], all_story_runs[0].story)

    self.assertEqual(2, len(all_story_runs))
    self.assertTrue(results.had_skips)
    self.assertTrue(all_story_runs[0].skipped)
    self.assertTrue(all_story_runs[1].ok)

  def testBenchmarkInterruption(self):
    reason = 'This is a reason'
    with self.CreateResults() as results:
      self.assertIsNone(results.benchmark_interruption)
      self.assertFalse(results.benchmark_interrupted)
      results.InterruptBenchmark(reason)

    self.assertEqual(results.benchmark_interruption, reason)
    self.assertTrue(results.benchmark_interrupted)

  def testUncaughtExceptionInterruptsBenchmark(self):
    with self.assertRaises(ValueError):
      with self.CreateResults() as results:
        results.WillRunPage(self.pages[0])
        raise ValueError('expected error')

    self.assertTrue(results.benchmark_interrupted)
    self.assertEqual(results.benchmark_interruption,
                     "ValueError('expected error',)")

  def testPassesNoSkips(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      results.Fail(_CreateException())
      results.DidRunPage(self.pages[0])

      results.WillRunPage(self.pages[1])
      results.DidRunPage(self.pages[1])

      results.WillRunPage(self.pages[2])
      results.Skip('testing reason')
      results.DidRunPage(self.pages[2])

    all_story_runs = list(results.IterStoryRuns())
    self.assertEqual(3, len(all_story_runs))
    self.assertTrue(all_story_runs[0].failed)
    self.assertTrue(all_story_runs[1].ok)
    self.assertTrue(all_story_runs[2].skipped)

  def testAddMeasurementAsScalar(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      results.AddMeasurement('a', 'seconds', 3)
      results.DidRunPage(self.pages[0])

    test_results = results_options.ReadTestResults(self.intermediate_dir)
    self.assertTrue(len(test_results), 1)
    measurements = results_options.ReadMeasurements(test_results[0])
    self.assertEqual(measurements, {'a': {'unit': 'seconds', 'samples': [3]}})

  def testAddMeasurementAsList(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      results.AddMeasurement('a', 'seconds', [1, 2, 3])
      results.DidRunPage(self.pages[0])

    test_results = results_options.ReadTestResults(self.intermediate_dir)
    self.assertTrue(len(test_results), 1)
    measurements = results_options.ReadMeasurements(test_results[0])
    self.assertEqual(measurements,
                     {'a': {'unit': 'seconds', 'samples': [1, 2, 3]}})

  def testNonNumericMeasurementIsInvalid(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      with self.assertRaises(TypeError):
        results.AddMeasurement('url', 'string', 'foo')
      results.DidRunPage(self.pages[0])

  def testMeasurementUnitChangeRaises(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      results.AddMeasurement('a', 'seconds', 3)
      results.DidRunPage(self.pages[0])

      results.WillRunPage(self.pages[1])
      with self.assertRaises(ValueError):
        results.AddMeasurement('a', 'foobgrobbers', 3)
      results.DidRunPage(self.pages[1])

  def testNoSuccessesWhenAllPagesFailOrSkip(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      results.Fail('message')
      results.DidRunPage(self.pages[0])

      results.WillRunPage(self.pages[1])
      results.Skip('message')
      results.DidRunPage(self.pages[1])

    self.assertFalse(results.had_successes)

  def testAddTraces(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      results.AddTraces(trace_data.CreateTestTrace(1))
      results.DidRunPage(self.pages[0])

      results.WillRunPage(self.pages[1])
      results.AddTraces(trace_data.CreateTestTrace(2))
      results.DidRunPage(self.pages[1])

    runs = list(results.IterRunsWithTraces())
    self.assertEqual(2, len(runs))

  def testAddTracesForSamePage(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      results.AddTraces(trace_data.CreateTestTrace(1))
      results.AddTraces(trace_data.CreateTestTrace(2))
      results.DidRunPage(self.pages[0])

    runs = list(results.IterRunsWithTraces())
    self.assertEqual(1, len(runs))

  def testDiagnosticsAsArtifact(self):
    with self.CreateResults(benchmark_name='some benchmark',
                            benchmark_description='a description') as results:
      results.AddSharedDiagnostics(
          owners=['test'],
          bug_components=['1', '2'],
          documentation_urls=[['documentation', 'url']],
          architecture='arch',
          device_id='id',
          os_name='os',
          os_version='ver',
      )
      results.WillRunPage(self.pages[0])
      results.DidRunPage(self.pages[0])
      results.WillRunPage(self.pages[1])
      results.DidRunPage(self.pages[1])

    records = self.GetResultRecords()
    self.assertEqual(len(records), 2)
    for record in records:
      self.assertEqual(record['testResult']['status'], 'PASS')
      artifacts = record['testResult']['outputArtifacts']
      self.assertIn(page_test_results.DIAGNOSTICS_NAME, artifacts)
      with open(artifacts[page_test_results.DIAGNOSTICS_NAME]['filePath']) as f:
        diagnostics = json.load(f)
      self.assertEqual(diagnostics, {
          'diagnostics': {
              'benchmarks': ['some benchmark'],
              'benchmarkDescriptions': ['a description'],
              'owners': ['test'],
              'bugComponents': ['1', '2'],
              'documentationLinks': [['documentation', 'url']],
              'architectures': ['arch'],
              'deviceIds': ['id'],
              'osNames': ['os'],
              'osVersions': ['ver'],
          },
      })

  def testCreateArtifactsForDifferentPages(self):
    with self.CreateResults() as results:
      results.WillRunPage(self.pages[0])
      with results.CreateArtifact('log.txt') as log_file:
        log_file.write('page0\n')
      results.DidRunPage(self.pages[0])

      results.WillRunPage(self.pages[1])
      with results.CreateArtifact('log.txt') as log_file:
        log_file.write('page1\n')
      results.DidRunPage(self.pages[1])

    all_story_runs = list(results.IterStoryRuns())
    log0_path = all_story_runs[0].GetArtifact('log.txt').local_path
    with open(log0_path) as f:
      self.assertEqual(f.read(), 'page0\n')

    log1_path = all_story_runs[1].GetArtifact('log.txt').local_path
    with open(log1_path) as f:
      self.assertEqual(f.read(), 'page1\n')
