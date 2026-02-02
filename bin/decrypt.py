#!/usr/bin/env python
# coding=utf-8

import csv
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "lib"))
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)
import decryptlib

FAILURE_FIELD = ".decrypt_failure__"


@Configuration()
class DecryptCommand(StreamingCommand):
    field = Option(require=False, default="_raw", validate=validators.Fieldname())

    def prepare(self) -> None:
        """Prepare for execution.

        This method should be overridden in search command classes that wish to examine and update their configuration
        or option settings prior to execution. It is called during the getinfo exchange before command metadata is sent
        to splunkd.
        """
        # this forces the field to exist at the end
        self.configuration.required_fields = [self.field]
        # this means we're only sent the field the user asked for
        self.configuration.clear_required_fields = True

    def stream(self, records):
        stmt = " ".join(self.fieldnames)
        try:
            for record in records:
                try:
                    decryptlib.g_record = record
                    decryptlib.logger = self.logger

                    if self.field in record:
                        result = record[self.field]

                        for fn, args in decryptlib.parse_statement(stmt):
                            result = fn(result, args)

                except Exception as e:
                    record[FAILURE_FIELD] = str(e)

                yield record
        except csv.Error:
            raise csv.Error(
                "Splunk record contained NUL. "
                "Use eval/replace or rex/sed beforehand to work around, "
                "or use the decrypt/escape function in the previous command."
                " (fixed in Python 3.11)"
            )


dispatch(DecryptCommand, sys.argv, sys.stdin, sys.stdout, __name__)
