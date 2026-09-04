#!/usr/bin/python
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# Copyright (c) 2020, One Identity LLC
# File: test_client_sw_pkgs.py
# Desc: Unit tests for the client_sw_pkgs module Solaris IPS (.p5p) discovery
#       helpers. Focus on failing discovery loudly for corrupt or incomplete
#       media rather than silently skipping a requested package.
# ------------------------------------------------------------------------------

import io
import os
import importlib.util
import tarfile
import tempfile
import shutil
import unittest


# ------------------------------------------------------------------------------
# Load the module by path so the tests do not require the collection to be
# installed into an ansible_collections tree.
# ------------------------------------------------------------------------------
_MODULE_PATH = os.path.join(
    os.path.dirname(__file__),
    '..', '..', '..', '..',
    'plugins', 'modules', 'client_sw_pkgs.py'
)

_spec = importlib.util.spec_from_file_location('client_sw_pkgs', _MODULE_PATH)
client_sw_pkgs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(client_sw_pkgs)


def _write_p5p(path, members):
    """
    Write a minimal USTAR .p5p tar. 'members' is a list of archive member
    names; each is added as an empty file, mirroring how a real .p5p carries a
    package manifest at publisher/<pub>/pkg/<name>/<encoded-version>.
    """
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as tar:
        for name in members:
            info = tarfile.TarInfo(name)
            info.size = 0
            tar.addfile(info, io.BytesIO(b''))


class P5pPackagesTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_valid_archive_reports_real_version(self):
        # The FMRI version is URL-encoded and carries the build branch after a
        # comma; the release before the comma is what must be reported.
        archive = os.path.join(self.tmp, 'sas.p5p')
        _write_p5p(archive, [
            'publisher/OneIdentity/pkg/vasclnts/1.2.3%2C5.11-0%3A20240101T000000Z',
        ])
        err, packages = client_sw_pkgs._p5p_packages(archive)
        self.assertIsNone(err)
        self.assertEqual(packages, {'vasclnts': '1.2.3'})

    def test_highest_version_wins(self):
        archive = os.path.join(self.tmp, 'sas.p5p')
        _write_p5p(archive, [
            'publisher/OneIdentity/pkg/vasclnt/1.2.3%2C5.11-0%3A20240101T000000Z',
            'publisher/OneIdentity/pkg/vasclnt/1.10.0%2C5.11-0%3A20240201T000000Z',
        ])
        err, packages = client_sw_pkgs._p5p_packages(archive)
        self.assertIsNone(err)
        # Numeric (not lexical) comparison: 1.10.0 > 1.2.3.
        self.assertEqual(packages, {'vasclnt': '1.10.0'})

    def test_unreadable_archive_returns_error(self):
        archive = os.path.join(self.tmp, 'corrupt.p5p')
        with open(archive, 'wb') as handle:
            handle.write(b'this is not a tar archive' * 8)
        err, packages = client_sw_pkgs._p5p_packages(archive)
        self.assertIsNotNone(err)
        self.assertIn(archive, err)
        self.assertEqual(packages, {})

    def test_readable_but_empty_archive_returns_error(self):
        # A tar-readable .p5p with no publisher/.../pkg/... manifests is
        # incomplete media and must be reported, not treated as "no packages".
        archive = os.path.join(self.tmp, 'empty.p5p')
        _write_p5p(archive, ['pkg5.repository', 'publisher/OneIdentity/catalog/x'])
        err, packages = client_sw_pkgs._p5p_packages(archive)
        self.assertIsNotNone(err)
        self.assertIn(archive, err)
        self.assertEqual(packages, {})


class FindPackagesSolarisIpsTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.base = os.path.join(self.tmp, 'solaris11-x64')
        os.makedirs(self.base)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _valid(self, fname, pkg, vers):
        _write_p5p(
            os.path.join(self.base, fname),
            ['publisher/OneIdentity/pkg/%s/%s%%2C5.11-0%%3A20240101T000000Z'
             % (pkg, vers)]
        )

    def test_valid_only_discovers_package(self):
        self._valid('sas.p5p', 'vasclnt', '7.1.0.6700')
        err, packages = client_sw_pkgs.find_packages_solaris_ips(self.tmp, 'x64')
        self.assertIsNone(err)
        self.assertIn('vasclnt', packages)
        self.assertEqual(packages['vasclnt']['vers'], '7.1.0.6700')

    def test_corrupt_archive_fails_discovery(self):
        self._valid('sas.p5p', 'vasclnt', '7.1.0.6700')
        corrupt = os.path.join(self.base, 'sas_site.p5p')
        with open(corrupt, 'wb') as handle:
            handle.write(b'not a tar' * 8)
        err, packages = client_sw_pkgs.find_packages_solaris_ips(self.tmp, 'x64')
        self.assertIsNotNone(err)
        self.assertIn('sas_site.p5p', err)
        self.assertEqual(packages, {})

    def test_empty_archive_fails_discovery(self):
        # Regression: a valid standard archive beside a tar-readable but
        # package-empty site archive must NOT pass discovery, otherwise a
        # requested site package (e.g. vasclnts) is silently skipped.
        self._valid('sas.p5p', 'vasclnt', '7.1.0.6700')
        _write_p5p(os.path.join(self.base, 'sas_site.p5p'), ['pkg5.repository'])
        err, packages = client_sw_pkgs.find_packages_solaris_ips(self.tmp, 'x64')
        self.assertIsNotNone(err)
        self.assertIn('sas_site.p5p', err)
        self.assertEqual(packages, {})


if __name__ == '__main__':
    unittest.main()
