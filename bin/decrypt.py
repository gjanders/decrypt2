#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import csv
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

import decryptlib

@Configuration()
class DecryptCommand(StreamingCommand):
    field = Option(
        require=False, default="_raw", validate=validators.Fieldname()
    )

    def stream(self, records):
        stmt = " ".join(self.fieldnames)

        try:
            for record in records:
                try:
                    decryptlib.g_record = record
                    decryptlib.logger = self.logger
                    exception_string = None

                    if self.field in record:
                        result = record[self.field]

                        for fn, args in decryptlib.parsestmt(stmt):
                            result = fn(result, args)

                except Exception as e:
                    exception_string = str(e)
                    record[".decrypt_failure__"] = exception_string

                yield record
        except csv.Error:
            raise csv.Error('Splunk record contained NUL. '
                            'Use eval/replace or rex/sed beforehand to work around, '
                            'or use the decrypt/escape function in the previous command.'
                            ' (fixed in Python 3.11)')


dispatch(DecryptCommand, sys.argv, sys.stdin, sys.stdout, __name__)

