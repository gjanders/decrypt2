#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals
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

            finally:
                record[".decrypt_failure__"] = exception_string 

            yield record


dispatch(DecryptCommand, sys.argv, sys.stdin, sys.stdout, __name__)

